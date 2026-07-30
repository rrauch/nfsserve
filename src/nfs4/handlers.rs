#![allow(non_camel_case_types)]
#![allow(dead_code)]

use anyhow::anyhow;
use num_traits::cast::FromPrimitive;
use std::io::{Cursor, Read, Write};
use tracing::{debug, warn};

use crate::context::RPCContext;
use crate::nfs;
use crate::nfs::{id_to_fh, nfsstring, write_verifier};
use crate::nfs4::state::{ManagedFileHandle, OwnerSeqid};
use crate::nfs4::*;
use crate::rpc::*;
use crate::vfs::OpenMode;
use crate::xdr::*;

const MAX_COMPOUND_OPS: u32 = 16;

/// Per-COMPOUND execution state.
struct CompoundState {
    minorversion: u32,
    current_fh: Option<nfs_fh4>,
    saved_fh: Option<nfs_fh4>,
    session: Option<SequenceContext>,
    opcount: usize,
}

impl CompoundState {
    fn new(minorversion: u32) -> Self {
        Self {
            minorversion,
            current_fh: None,
            saved_fh: None,
            session: None,
            opcount: 0,
        }
    }

    /// In 4.0 there is no session, so this is a no-op. In 4.1 every op after
    /// SEQUENCE requires a bound session.
    fn require_session(&self) -> Result<(), OpError> {
        if self.minorversion == 0 {
            return Ok(());
        }
        if self.session.is_none() {
            Err(nfsstat4::NFS4ERR_OP_NOT_IN_SESSION.into())
        } else {
            Ok(())
        }
    }

    fn current_fh(&self) -> Result<&nfs_fh4, OpError> {
        self.current_fh.as_ref().ok_or(nfsstat4::NFS4ERR_NOFILEHANDLE.into())
    }

    fn saved_fh(&self) -> Result<&nfs_fh4, OpError> {
        self.saved_fh.as_ref().ok_or(nfsstat4::NFS4ERR_NOFILEHANDLE.into())
    }
}

struct SequenceContext {
    sessionid: sessionid4,
    slotid: slotid4,
    sequenceid: sequenceid4,
    cache_this: bool,
}

enum OpError {
    Status(nfsstat4),
    Fatal(anyhow::Error),
}

impl From<nfsstat4> for OpError {
    fn from(s: nfsstat4) -> Self {
        OpError::Status(s)
    }
}

impl From<anyhow::Error> for OpError {
    fn from(e: anyhow::Error) -> Self {
        OpError::Fatal(e)
    }
}

impl From<std::io::Error> for OpError {
    fn from(value: std::io::Error) -> Self {
        anyhow::Error::from(value).into()
    }
}

impl From<crate::nfs3::nfsstat3> for OpError {
    fn from(e: crate::nfs3::nfsstat3) -> Self {
        OpError::Status(nfsstat4::from(e))
    }
}

/// Assert `attr.ftype` is `$want`, else return `$otherwise`.
/// Also encodes the common NF4DIR special-case for regular-file ops.
macro_rules! ensure_ftype {
    ($attr:expr, $want:path, $otherwise:expr) => {{
        match $attr.ftype {
            Some($want) => {},
            other => {
                let _ = other;
                return Err($otherwise.into());
            },
        }
    }};
}

// ---------------------------------------------------------------------------
// VFS helpers (map errors to OpError, fold in the common ftype checks).
// ---------------------------------------------------------------------------

fn fh_to_id(context: &RPCContext, fh: &nfs_fh4) -> Result<fileid4, OpError> {
    Ok(nfs::fh_to_id(context.epoch, fh)?)
}

async fn getattr4(context: &RPCContext, id: fileid4) -> Result<fattr4, OpError> {
    let a = context.vfs.getattr(id).await?;
    let fsinfo = context.vfs.fsinfo(a.fileid).await?;
    Ok(fattr4::from_v3(&a, &fsinfo))
}

/// getattr + assert directory; returns the fattr4 (for change-id extraction).
async fn require_dir(context: &RPCContext, id: fileid4) -> Result<fattr4, OpError> {
    let a = getattr4(context, id).await?;
    ensure_ftype!(a, ftype4::NF4DIR, nfsstat4::NFS4ERR_NOTDIR);
    Ok(a)
}

/// getattr + assert regular file (ISDIR / INVAL on mismatch).
async fn require_reg(context: &RPCContext, id: fileid4) -> Result<(), OpError> {
    let a = getattr4(context, id).await?;
    match a.ftype {
        Some(ftype4::NF4REG) => Ok(()),
        Some(ftype4::NF4DIR) => Err(nfsstat4::NFS4ERR_ISDIR.into()),
        _ => Err(nfsstat4::NFS4ERR_INVAL.into()),
    }
}

/// getattr + assert symlink (ISDIR / INVAL on mismatch).
async fn require_symlink(context: &RPCContext, id: fileid4) -> Result<(), OpError> {
    let a = getattr4(context, id).await?;
    match a.ftype {
        Some(ftype4::NF4LNK) => Ok(()),
        Some(ftype4::NF4DIR) => Err(nfsstat4::NFS4ERR_ISDIR.into()),
        _ => Err(nfsstat4::NFS4ERR_INVAL.into()),
    }
}

fn require_writable(context: &RPCContext) -> Result<(), OpError> {
    if matches!(context.vfs.capabilities(), crate::vfs::VFSCapabilities::ReadOnly) {
        Err(nfsstat4::NFS4ERR_ROFS.into())
    } else {
        Ok(())
    }
}

fn change_before(attr: &fattr4) -> changeid4 {
    attr.change.unwrap_or_default()
}

async fn change_after(context: &RPCContext, id: fileid4, fallback: changeid4) -> changeid4 {
    context
        .vfs
        .getattr(id)
        .await
        .map(|a| a.ctime.seconds as changeid4)
        .unwrap_or(fallback)
}

/// Which access bit a stateid must carry.
#[derive(Clone, Copy)]
enum Need {
    Read,
    Write,
}

/// Validate a stateid against the current file: special stateids are always
/// allowed; open stateids must match the file and carry the needed access.
fn check_stateid(
    context: &RPCContext,
    stateid: &stateid4,
    fileid: fileid4,
    need: Need,
) -> Result<Option<ManagedFileHandle>, OpError> {
    use super::state::Resolved;
    let cid = context.client_id().ok_or_else(|| nfsstat4::NFS4ERR_BAD_STATEID)?;
    match context.nfs4_state.resolve(cid, stateid)? {
        Resolved::Anonymous | Resolved::Bypass => Ok(None),
        Resolved::Open {
            fileid: sid_fileid,
            fh: vfs_fh,
            mode,
        } => {
            if sid_fileid != fileid {
                return Err(nfsstat4::NFS4ERR_BAD_STATEID.into());
            }
            match (need, mode) {
                (Need::Read, OpenMode::ReadOnly) => {},
                (Need::Write, OpenMode::ReadWrite) => {},
                _ => return Err(nfsstat4::NFS4ERR_OPENMODE.into()),
            }
            Ok(Some(vfs_fh))
        },
    }
}

// ---------------------------------------------------------------------------
// Top-level dispatch.
// ---------------------------------------------------------------------------

pub async fn handle_nfs(
    xid: u32,
    call: call_body,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    match call.proc {
        0 => nfsproc4_null(xid, output),
        1 => nfsproc4_compound(xid, input, output, context).await,
        _ => {
            warn!("nfs4: unknown proc {}", call.proc);
            proc_unavail_reply_message(xid).serialize(output)?;
            Ok(())
        },
    }
}

fn nfsproc4_null(xid: u32, output: &mut impl Write) -> Result<(), anyhow::Error> {
    debug!("nfsproc4_null({})", xid);
    make_success_reply(xid).serialize(output)?;
    Ok(())
}

/*
COMPOUND4args:
    utf8str_cs tag;
    uint32     minorversion;
    nfs_argop4 argarray<>;

COMPOUND4res:
    nfsstat4   status;
    utf8str_cs tag;
    nfs_resop4 resarray<>;
*/
async fn nfsproc4_compound(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut tag = nfsstring::default();
    tag.deserialize(input)?;
    let mut minorversion: u32 = 0;
    minorversion.deserialize(input)?;
    let mut num_ops: u32 = 0;
    num_ops.deserialize(input)?;

    debug!("nfs4 COMPOUND xid={} tag={:?} minor={} nops={}", xid, tag, minorversion, num_ops);

    if minorversion > 1 {
        make_success_reply(xid).serialize(output)?;
        nfsstat4::NFS4ERR_MINOR_VERS_MISMATCH.serialize(output)?;
        tag.serialize(output)?;
        0u32.serialize(output)?;
        return Ok(());
    }

    if num_ops > MAX_COMPOUND_OPS {
        make_success_reply(xid).serialize(output)?;
        nfsstat4::NFS4ERR_TOO_MANY_OPS.serialize(output)?;
        return Ok(());
    }

    let mut state = CompoundState::new(minorversion);
    let mut result_buf: Vec<u8> = Vec::new();
    let mut rescount: u32 = 0;
    let mut last_status = nfsstat4::NFS4_OK;

    for _ in 0..num_ops {
        let mut opnum_raw: u32 = 0;
        opnum_raw.deserialize(input)?;

        let mut op_out = Cursor::new(Vec::<u8>::new());
        opnum_raw.serialize(&mut op_out)?;

        let dispatch = match nfs_opnum4::from_u32(opnum_raw) {
            Some(op) => dispatch_op(op, input, &mut op_out, &mut state, context).await?,
            None => {
                warn!("nfs4: illegal/unknown opnum {}", opnum_raw);
                let mut illegal = Cursor::new(Vec::<u8>::new());
                nfs_opnum4::OP_ILLEGAL.serialize(&mut illegal)?;
                nfsstat4::NFS4ERR_OP_ILLEGAL.serialize(&mut illegal)?;
                op_out = illegal;
                DispatchResult::Status(nfsstat4::NFS4ERR_OP_ILLEGAL)
            },
        };

        if let DispatchResult::Replay(cached) = dispatch {
            make_success_reply(xid).serialize(output)?;
            output.write_all(&cached)?;
            return Ok(());
        }

        let status = dispatch.status();

        rescount += 1;
        result_buf.extend_from_slice(&op_out.into_inner());
        last_status = status;
        state.opcount += 1;

        if status != nfsstat4::NFS4_OK {
            break;
        }
    }

    let mut body: Vec<u8> = Vec::new();
    last_status.serialize(&mut body)?;
    tag.serialize(&mut body)?;
    rescount.serialize(&mut body)?;
    body.extend_from_slice(&result_buf);

    if let Some(seq) = &state.session {
        if seq.cache_this {
            let cid = context.client_id().ok_or_else(|| anyhow!("client_id missing"))?;
            context
                .nfs4_state
                .cache_reply(cid, &seq.sessionid, seq.slotid, seq.sequenceid, body.clone());
        }
    }

    make_success_reply(xid).serialize(output)?;
    output.write_all(&body)?;
    Ok(())
}

enum DispatchResult {
    Status(nfsstat4),
    Replay(Vec<u8>),
}

impl DispatchResult {
    fn status(&self) -> nfsstat4 {
        match self {
            DispatchResult::Status(s) => *s,
            DispatchResult::Replay(_) => nfsstat4::NFS4_OK,
        }
    }
}

/// Dispatch a single op. The op body has already had its opnum consumed
/// from `input` and echoed into `op_out`.
async fn dispatch_op(
    op: nfs_opnum4,
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<DispatchResult, anyhow::Error> {
    use nfs_opnum4::*;

    macro_rules! run {
        ($fut:expr) => {
            match $fut.await {
                Ok(()) => DispatchResult::Status(nfsstat4::NFS4_OK),
                Err(OpError::Status(s)) => {
                    s.serialize(op_out)?;
                    DispatchResult::Status(s)
                },
                Err(OpError::Fatal(e)) => return Err(e),
            }
        };
    }

    // Cross-version rejection.
    let v = state.minorversion;
    let is_v41_only = matches!(
        op,
        OP_EXCHANGE_ID
            | OP_CREATE_SESSION
            | OP_DESTROY_SESSION
            | OP_DESTROY_CLIENTID
            | OP_SEQUENCE
            | OP_RECLAIM_COMPLETE
            | OP_SECINFO_NO_NAME
    );
    let is_v40_only =
        matches!(op, OP_SETCLIENTID | OP_SETCLIENTID_CONFIRM | OP_RENEW | OP_OPEN_CONFIRM | OP_RELEASE_LOCKOWNER);
    if (v != 1 && is_v41_only) || (v != 0 && is_v40_only) {
        warn!("nfs4: op {:?} not valid in minorversion {}", op, v);
        nfsstat4::NFS4ERR_NOTSUPP.serialize(op_out)?;
        return Ok(DispatchResult::Status(nfsstat4::NFS4ERR_NOTSUPP));
    }

    let res = match op {
        // ---- NFSv4.1 session/clientid management ----
        OP_EXCHANGE_ID => run!(op_exchange_id(input, op_out, context)),
        OP_CREATE_SESSION => run!(op_create_session(input, op_out, context)),
        OP_DESTROY_SESSION => run!(op_destroy_session(input, op_out, state, context)),
        OP_DESTROY_CLIENTID => run!(op_destroy_clientid(input, op_out, context)),
        OP_SEQUENCE => match op_sequence(input, op_out, state, context).await {
            Ok(res) => res,
            Err(OpError::Status(s)) => {
                s.serialize(op_out)?;
                DispatchResult::Status(s)
            },
            Err(OpError::Fatal(e)) => return Err(e),
        },
        OP_RECLAIM_COMPLETE => run!(op_reclaim_complete(input, op_out, state, context)),
        OP_SECINFO_NO_NAME => run!(op_secinfo_no_name(input, op_out, state, context)),

        // ---- NFSv4.0 clientid management ----
        OP_SETCLIENTID => run!(op_setclientid(input, op_out, context)),
        OP_SETCLIENTID_CONFIRM => run!(op_setclientid_confirm(input, op_out, context)),
        OP_RENEW => run!(op_renew(input, op_out, context)),
        OP_OPEN_CONFIRM => run!(op_open_confirm(input, op_out, state, context)),
        OP_RELEASE_LOCKOWNER => run!(op_release_lockowner(input, op_out, context)),

        OP_PUTROOTFH => run!(op_putrootfh(op_out, state, context)),
        OP_GETFH => run!(op_getfh(op_out, state)),
        OP_GETATTR => run!(op_getattr(input, op_out, state, context)),
        OP_PUTFH => run!(op_putfh(input, op_out, state, context)),
        OP_ACCESS => run!(op_access(input, op_out, state, context)),
        OP_LOOKUP => run!(op_lookup(input, op_out, state, context)),
        OP_READDIR => run!(op_readdir(input, op_out, state, context)),
        OP_OPEN => run!(op_open(input, op_out, state, context)),
        OP_CLOSE => run!(op_close(input, op_out, state, context)),
        OP_READ => run!(op_read(input, op_out, state, context)),
        OP_WRITE => run!(op_write(input, op_out, state, context)),
        OP_REMOVE => run!(op_remove(input, op_out, state, context)),
        OP_CREATE => run!(op_create(input, op_out, state, context)),
        OP_SAVEFH => run!(op_savefh(op_out, state)),
        OP_RESTOREFH => run!(op_restorefh(op_out, state)),
        OP_RENAME => run!(op_rename(input, op_out, state, context)),
        OP_SETATTR => op_setattr(input, op_out, state, context).await.map(DispatchResult::Status)?,
        OP_READLINK => run!(op_readlink(op_out, state, context)),
        OP_COMMIT => run!(op_commit(input, op_out, state, context)),
        OP_TEST_STATEID => run!(op_test_stateid(input, op_out, state, context)),
        OP_SECINFO => run!(op_secinfo(input, op_out, state, context)),
        other => {
            warn!("nfs4: unimplemented op {:?}", other);
            nfsstat4::NFS4ERR_NOTSUPP.serialize(op_out)?;
            DispatchResult::Status(nfsstat4::NFS4ERR_NOTSUPP)
        },
    };
    Ok(res)
}

/// OP_EXCHANGE_ID (RFC 8881 §18.35).
/// SP4_NONE only, non-pNFS
async fn op_exchange_id(input: &mut impl Read, op_out: &mut impl Write, context: &RPCContext) -> Result<(), OpError> {
    let mut args = EXCHANGE_ID4args::default();
    args.deserialize(input)?;

    debug!(
        "OP_EXCHANGE_ID owner={:?} flags={:#x} how={:?}",
        nfsstring::from(args.eia_clientowner.co_ownerid.clone()),
        args.eia_flags,
        args.eia_state_protect.spa_how
    );

    if args.eia_state_protect.spa_how != state_protect_how4::SP4_NONE {
        return Err(nfsstat4::NFS4ERR_NOTSUPP.into());
    }

    let (clientid, seqid) = context
        .nfs4_state
        .exchange_id(&args.eia_clientowner.co_ownerid, &args.eia_clientowner.co_verifier);

    context.set_client_id(clientid);

    let resok = EXCHANGE_ID4resok {
        eir_clientid: clientid,
        eir_sequenceid: seqid,
        eir_flags: EXCHGID4_FLAG_USE_NON_PNFS,
        eir_state_protect: state_protect4_r {
            spr_how: state_protect_how4::SP4_NONE,
        },
        eir_server_owner: server_owner4 {
            so_minor_id: 0,
            so_major_id: format!("nfs4-server:{}", context.local_port).into_bytes(),
        },
        eir_server_scope: b"nfs4-server-scope".to_vec(),
        eir_server_impl_id: impl_id_optional(None),
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_CREATE_SESSION (RFC 8881 §18.36).
/// single-slot fore channel, no back channel, no persistence.
async fn op_create_session(
    input: &mut impl Read,
    op_out: &mut impl Write,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = CREATE_SESSION4args::default();
    args.deserialize(input)?;

    debug!(
        "OP_CREATE_SESSION clientid={:#x} seq={} flags={:#x} \
         fore(maxreq={},maxreqsz={},maxrespsz={},maxops={}) cb_prog={}",
        args.csa_clientid,
        args.csa_sequence,
        args.csa_flags,
        args.csa_fore_chan_attrs.ca_maxrequests,
        args.csa_fore_chan_attrs.ca_maxrequestsize,
        args.csa_fore_chan_attrs.ca_maxresponsesize,
        args.csa_fore_chan_attrs.ca_maxoperations,
        args.csa_cb_program,
    );

    const MAX_REQUESTS: u32 = 1;

    let fore = channel_attrs4 {
        ca_headerpadsize: 0,
        ca_maxrequestsize: args.csa_fore_chan_attrs.ca_maxrequestsize.min(MAX_REQUEST_SIZE),
        ca_maxresponsesize: args.csa_fore_chan_attrs.ca_maxresponsesize.min(MAX_RESPONSE_SIZE),
        ca_maxresponsesize_cached: args.csa_fore_chan_attrs.ca_maxresponsesize_cached.min(MAX_RESPONSE_SIZE),
        ca_maxoperations: args.csa_fore_chan_attrs.ca_maxoperations.min(MAX_COMPOUND_OPS).max(1),
        ca_maxrequests: args.csa_fore_chan_attrs.ca_maxrequests.min(MAX_REQUESTS).max(1),
        ca_rdma_ird: Vec::new(),
    };

    let back = channel_attrs4 {
        ca_headerpadsize: 0,
        ca_maxrequestsize: 0,
        ca_maxresponsesize: 0,
        ca_maxresponsesize_cached: 0,
        ca_maxoperations: 0,
        ca_maxrequests: 0,
        ca_rdma_ird: Vec::new(),
    };

    let num_slots = fore.ca_maxrequests;

    use super::state::CreateSession::*;
    let sessionid = match context.nfs4_state.create_session(
        args.csa_clientid,
        args.csa_sequence,
        num_slots,
        fore.ca_maxresponsesize_cached,
    )? {
        New(sessionid) | Replay(sessionid) => sessionid,
    };

    let resok = CREATE_SESSION4resok {
        csr_sessionid: sessionid,
        csr_sequence: args.csa_sequence,
        csr_flags: 0,
        csr_fore_chan_attrs: fore,
        csr_back_chan_attrs: back,
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_DESTROY_SESSION (RFC 8881 §18.37).
async fn op_destroy_session(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = DESTROY_SESSION4args::default();
    args.deserialize(input)?;

    debug!("OP_DESTROY_SESSION sessionid={:x?}", args.dsa_sessionid);

    let destroying_current = state
        .session
        .as_ref()
        .map(|s| s.sessionid == args.dsa_sessionid)
        .unwrap_or(false);
    if destroying_current {
        state.session = None;
    }
    let cid = context.client_id().ok_or_else(|| nfsstat4::NFS4ERR_BAD_STATEID)?;
    context.nfs4_state.destroy_session(cid, &args.dsa_sessionid)?;
    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_DESTROY_CLIENTID (RFC 8881 §18.50).
async fn op_destroy_clientid(
    input: &mut impl Read,
    op_out: &mut impl Write,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = DESTROY_CLIENTID4args::default();
    args.deserialize(input)?;

    debug!("OP_DESTROY_CLIENTID clientid={:#x}", args.dca_clientid);

    context.nfs4_state.destroy_clientid(args.dca_clientid)?;
    context.clear_client_id();
    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// SEQUENCE keeps its native signature: it can return Replay and must
/// serialize its own error statuses (it runs before the session is bound).
async fn op_sequence(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<DispatchResult, OpError> {
    let mut args = SEQUENCE4args::default();
    args.deserialize(input)?;

    debug!(
        "OP_SEQUENCE session={:x?} seq={} slot={} high={} cache={}",
        args.sa_sessionid, args.sa_sequenceid, args.sa_slotid, args.sa_highest_slotid, args.sa_cachethis
    );

    if state.opcount != 0 {
        nfsstat4::NFS4ERR_SEQUENCE_POS.serialize(op_out)?;
        return Ok(DispatchResult::Status(nfsstat4::NFS4ERR_SEQUENCE_POS));
    }

    let cid = context.client_id().ok_or_else(|| nfsstat4::NFS4ERR_BAD_STATEID)?;

    use super::state::Sequence::*;
    let status = match context
        .nfs4_state
        .sequence(cid, &args.sa_sessionid, args.sa_slotid, args.sa_sequenceid)?
    {
        New => nfsstat4::NFS4_OK,
        Replay(cached) => return Ok(DispatchResult::Replay(cached)),
        RetryUncached => nfsstat4::NFS4ERR_RETRY_UNCACHED_REP,
    };

    if status != nfsstat4::NFS4_OK {
        status.serialize(op_out)?;
        return Ok(DispatchResult::Status(status));
    }

    state.session = Some(SequenceContext {
        sessionid: args.sa_sessionid,
        slotid: args.sa_slotid,
        sequenceid: args.sa_sequenceid,
        cache_this: args.sa_cachethis,
    });

    let resok = SEQUENCE4resok {
        sr_sessionid: args.sa_sessionid,
        sr_sequenceid: args.sa_sequenceid,
        sr_slotid: args.sa_slotid,
        sr_highest_slotid: 0,
        sr_target_highest_slotid: 0,
        sr_status_flags: 0,
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(DispatchResult::Status(nfsstat4::NFS4_OK))
}

/// OP_RECLAIM_COMPLETE (RFC 8881 §18.51).
/// The client has finished (or has no) state to reclaim. Since we hold no
/// persistent state and grant no delegations, this is an acknowledgement.
/// We record that reclaim is done so a strict server could reject late
/// CLAIM_PREVIOUS opens; here it's informational.
async fn op_reclaim_complete(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = RECLAIM_COMPLETE4args::default();
    args.deserialize(input)?;

    state.require_session()?;

    debug!("OP_RECLAIM_COMPLETE one_fs={}", args.rca_one_fs);

    if let Some(session) = &state.session {
        let cid = context.client_id().ok_or_else(|| nfsstat4::NFS4ERR_BAD_STATEID)?;
        context.nfs4_state.reclaim_complete(cid, &session.sessionid)?;
    }

    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_SECINFO_NO_NAME (RFC 8881 §18.45).
/// Reports supported security flavors. We support AUTH_SYS and AUTH_NONE.
/// The current filehandle must be set (both styles require it: CURRENT_FH
/// uses it directly; PARENT requires it to derive the parent).
async fn op_secinfo_no_name(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = SECINFO_NO_NAME4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    let fh = state.current_fh()?;
    fh_to_id(context, fh)?; // validate STALE/BADHANDLE

    debug!("OP_SECINFO_NO_NAME style={:?}", args.style);

    let flavors = vec![
        secinfo4 {
            flavor: AUTH_SYS,
            gss_info: None,
        },
        secinfo4 {
            flavor: AUTH_NONE,
            gss_info: None,
        },
    ];

    nfsstat4::NFS4_OK.serialize(op_out)?;
    flavors.serialize(op_out)?;

    // SECINFO_NO_NAME consumes the current filehandle.
    state.current_fh = None;
    Ok(())
}

/// OP_SECINFO (RFC 8881 §18.29, RFC 7530 §16.31).
/// Looks up `name` in the current directory FH and reports supported security
/// flavors. Per spec the current filehandle is consumed on success.
async fn op_secinfo(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = SECINFO4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    if args.name.0.is_empty() {
        return Err(nfsstat4::NFS4ERR_INVAL.into());
    }

    let dir_fh = state.current_fh()?;
    let dirid = fh_to_id(context, dir_fh)?;
    require_dir(context, dirid).await?;

    let name: filename4 = args.name.0.clone().into();
    debug!("OP_SECINFO dir={} name={:?}", dirid, args.name);

    // The named entry must exist.
    context.vfs.lookup(dirid, &name).await?;

    let flavors = vec![
        secinfo4 {
            flavor: AUTH_SYS,
            gss_info: None,
        },
        secinfo4 {
            flavor: AUTH_NONE,
            gss_info: None,
        },
    ];

    nfsstat4::NFS4_OK.serialize(op_out)?;
    flavors.serialize(op_out)?;

    // SECINFO consumes the current filehandle.
    state.current_fh = None;
    Ok(())
}

/// OP_PUTROOTFH (RFC 8881 §18.21).
/// Sets the current filehandle to the export root.
async fn op_putrootfh(op_out: &mut impl Write, state: &mut CompoundState, context: &RPCContext) -> Result<(), OpError> {
    state.require_session()?;

    let root = context.vfs.root_dir();
    let fh = id_to_fh(context.epoch, root);

    debug!("OP_PUTROOTFH root_id={} fh={:x?}", root, fh.data);

    state.current_fh = Some(fh);

    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

async fn op_getfh(op_out: &mut impl Write, state: &mut CompoundState) -> Result<(), OpError> {
    state.require_session()?;
    let fh = state.current_fh()?;

    debug!("OP_GETFH fh={:x?}", fh.data);

    nfsstat4::NFS4_OK.serialize(op_out)?;
    fh.serialize(op_out)?;
    Ok(())
}

/// OP_GETATTR (RFC 8881 §18.7).
async fn op_getattr(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = GETATTR4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    let fh = state.current_fh()?.clone();
    let id = fh_to_id(context, &fh)?;

    debug!("OP_GETATTR id={} req={:x?}", id, args.attr_request);

    let mut attr = getattr4(context, id).await?;
    attr.filehandle = Some(fh);
    attr.retain_requested(&args.attr_request);

    nfsstat4::NFS4_OK.serialize(op_out)?;
    attr.serialize(op_out)?;
    Ok(())
}

/// OP_PUTFH (RFC 8881 §18.19).
/// Sets the current filehandle to the supplied value.
async fn op_putfh(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = PUTFH4args::default();
    args.deserialize(input)?;

    state.require_session()?;

    debug!("OP_PUTFH fh={:x?}", args.object.data);

    fh_to_id(context, &args.object)?; // validate now
    state.current_fh = Some(args.object);

    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_ACCESS (RFC 8881 §18.1).
/// Derives granted access from file mode + our export capability.
/// We do not do per-user permission enforcement here (AUTH_SYS, lean).
async fn op_access(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = ACCESS4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    let fh = state.current_fh()?;
    let id = fh_to_id(context, fh)?;

    let attr = getattr4(context, id).await?;
    let is_dir = matches!(attr.ftype, Some(ftype4::NF4DIR));
    let read_only = matches!(context.vfs.capabilities(), crate::vfs::VFSCapabilities::ReadOnly);

    let supported = if is_dir {
        ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE
    } else {
        ACCESS4_READ | ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_EXECUTE
    };

    let mut granted = supported;
    if read_only {
        granted &= !(ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE);
    }

    let access = granted & args.access;
    let supported = supported & args.access;

    debug!("OP_ACCESS id={} req={:#x} supported={:#x} granted={:#x}", id, args.access, supported, access);

    let resok = ACCESS4resok { supported, access };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_LOOKUP (RFC 8881 §18.13).
/// Resolves `objname` in the current directory FH; on success the current
/// FH becomes the named object.
async fn op_lookup(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = LOOKUP4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    if args.objname.0.is_empty() {
        return Err(nfsstat4::NFS4ERR_INVAL.into());
    }

    let fh = state.current_fh()?;
    let dirid = fh_to_id(context, fh)?;
    require_dir(context, dirid).await?;

    let name: filename4 = args.objname.0.clone().into();
    debug!("OP_LOOKUP dir={} name={:?}", dirid, args.objname);

    let objid = context.vfs.lookup(dirid, &name).await?;
    state.current_fh = Some(id_to_fh(context.epoch, objid));

    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_READDIR (RFC 8881 §18.23).
/// Cookie == fileid of last returned entry (0 => from start). No cookie
/// verifier is used (matches the VFS contract). Honors maxcount as a hard
/// byte budget on the encoded result.
async fn op_readdir(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = READDIR4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    let fh = state.current_fh()?;
    let dirid = fh_to_id(context, fh)?;
    require_dir(context, dirid).await?;

    if args.maxcount == 0 {
        return Err(nfsstat4::NFS4ERR_TOOSMALL.into());
    }

    let start_after = args.cookie;
    let max_entries = 256usize;
    let listing = context.vfs.readdir(dirid, start_after, max_entries).await?;

    debug!(
        "OP_READDIR dir={} cookie={} maxcount={} vfs_entries={} vfs_end={}",
        dirid,
        args.cookie,
        args.maxcount,
        listing.entries.len(),
        listing.end
    );

    let fixed_overhead: usize = 4 + NFS4_VERIFIER_SIZE + 4 + 4;
    let budget = args.maxcount as usize;

    let mut entries_buf: Vec<u8> = Vec::new();
    let mut used = fixed_overhead;
    let mut written_any = false;
    let mut truncated = false;

    let fsinfo = context.vfs.fsinfo(context.vfs.root_dir()).await?;

    for e in &listing.entries {
        let mut attr = fattr4::from_v3(&e.attr, &fsinfo);
        attr.filehandle = Some(id_to_fh(context.epoch, e.fileid));
        attr.retain_requested(&args.attr_request);

        let mut ent = Vec::new();
        true.serialize(&mut ent)?;
        (e.fileid as nfs_cookie4).serialize(&mut ent)?;
        let name: nfsstring = e.name.clone().into();
        name.serialize(&mut ent)?;
        attr.serialize(&mut ent)?;

        if used + ent.len() > budget {
            truncated = true;
            break;
        }
        used += ent.len();
        entries_buf.extend_from_slice(&ent);
        written_any = true;
    }

    if !written_any && !listing.entries.is_empty() {
        return Err(nfsstat4::NFS4ERR_TOOSMALL.into());
    }

    let eof = listing.end && !truncated;

    nfsstat4::NFS4_OK.serialize(op_out)?;
    let zero_verf: verifier4 = [0u8; NFS4_VERIFIER_SIZE];
    zero_verf.serialize(op_out)?;
    op_out.write_all(&entries_buf)?;
    false.serialize(op_out)?;
    eof.serialize(op_out)?;
    Ok(())
}

/// OP_OPEN (RFC 8881 §18.16).
/// CLAIM_NULL & CLAIM_FH only, OPEN4_NOCREATE + OPEN4_CREATE/UNCHECKED4,
/// always-grant shares, never delegates..
async fn op_open(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = OPEN4args::default();
    args.deserialize(input)?;

    state.require_session()?;

    debug!(
        "OP_OPEN seqid={} access={:#x} deny={:#x} owner_clientid={:#x} type={:?} claim={:?}",
        args.seqid, args.share_access, args.share_deny, args.owner.clientid, args.openhow.opentype, args.claim.claim,
    );

    let acc = args.share_access & OPEN4_SHARE_ACCESS_BOTH;
    if acc == 0 {
        return Err(nfsstat4::NFS4ERR_INVAL.into());
    }

    let read_only = matches!(context.vfs.capabilities(), crate::vfs::VFSCapabilities::ReadOnly);
    let wants_write = acc & OPEN4_SHARE_ACCESS_WRITE != 0;
    let creating = args.openhow.opentype == opentype4::OPEN4_CREATE;
    if read_only && (wants_write || creating) {
        return Err(nfsstat4::NFS4ERR_ROFS.into());
    }

    let mut created = false;
    let mut dir_change_before: changeid4 = 0;
    let mut dir_change_after: changeid4 = 0;

    let fileid = match args.claim.claim {
        open_claim_type4::CLAIM_NULL => {
            let dir_fh = state.current_fh()?;
            let dirid = fh_to_id(context, dir_fh)?;
            let dir_attr = require_dir(context, dirid).await?;
            dir_change_before = change_before(&dir_attr);

            let name: filename4 = args.claim.file.0.clone().into();
            if name.0.is_empty() {
                return Err(nfsstat4::NFS4ERR_INVAL.into());
            }

            let id = match context.vfs.lookup(dirid, &name).await.map_err(nfsstat4::from) {
                Ok(id) => id,
                Err(nfsstat4::NFS4ERR_NOENT) if creating => {
                    let attr = crate::nfs3::sattr3::default();
                    let (id, _) = context.vfs.create(dirid, &name, attr).await?;
                    created = true;
                    id
                },
                Err(status) => return Err(status.into()),
            };

            dir_change_after = if created {
                change_after(context, dirid, dir_change_before).await
            } else {
                dir_change_before
            };
            id
        },

        open_claim_type4::CLAIM_FH => {
            if creating {
                return Err(nfsstat4::NFS4ERR_INVAL.into());
            }
            let fh = state.current_fh()?;
            fh_to_id(context, fh)?
        },

        _ => return Err(nfsstat4::NFS4ERR_NOTSUPP.into()),
    };

    // Target must be a regular file. (SYMLINK for other non-dir types.)
    let target_attr = getattr4(context, fileid).await?;
    match target_attr.ftype {
        Some(ftype4::NF4REG) => {},
        Some(ftype4::NF4DIR) => return Err(nfsstat4::NFS4ERR_ISDIR.into()),
        _ => return Err(nfsstat4::NFS4ERR_SYMLINK.into()),
    }

    let mode = if wants_write || creating {
        OpenMode::ReadWrite
    } else {
        OpenMode::ReadOnly
    };

    let seqid = if state.minorversion == 0 {
        OwnerSeqid::V40(args.seqid)
    } else {
        OwnerSeqid::V41
    };

    let opened = context
        .nfs4_state
        .open(args.owner.clientid, &args.owner.owner, seqid, fileid, mode)
        .await?;

    state.current_fh = Some(id_to_fh(context.epoch, fileid));

    // NFSv4.0: a fresh open owner must be confirmed via OPEN_CONFIRM before
    // its stateids are usable. 4.1 has no OPEN_CONFIRM.
    let need_confirm = state.minorversion == 0 && opened.confirm_required;

    let rflags = if need_confirm { OPEN4_RESULT_CONFIRM } else { 0 };

    let resok = OPEN4resok {
        stateid: opened.stateid,
        cinfo: change_info4 {
            atomic: false,
            before: dir_change_before,
            after: dir_change_after,
        },
        rflags,
        attrset: Vec::new(),
        delegation: open_delegation4_none,
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// CLOSE has a custom error tail (BAD_STATEID with no stateid payload), so it
/// serializes its own status and always returns Ok(()).
async fn op_close(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = CLOSE4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    state.current_fh()?; // require FH

    debug!(
        "OP_CLOSE seqid={} stateid.seqid={} stateid.other={:x?}",
        args.seqid, args.open_stateid.seqid, args.open_stateid.other
    );

    let seqid = if state.minorversion == 0 {
        OwnerSeqid::V40(args.seqid)
    } else {
        OwnerSeqid::V41
    };

    let cid = context.client_id().ok_or_else(|| nfsstat4::NFS4ERR_BAD_STATEID)?;
    let stateid = context.nfs4_state.close(cid, &args.open_stateid, seqid)?;
    nfsstat4::NFS4_OK.serialize(op_out)?;
    stateid.serialize(op_out)?;
    Ok(())
}

/// OP_READ (RFC 8881 §18.22).
/// Reads from the current filehandle. The stateid must be a known open
/// stateid or a special (anonymous) stateid.
async fn op_read(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = READ4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    let fh = state.current_fh()?;
    let fh_fileid = fh_to_id(context, fh)?;

    let vfs_fh =
        check_stateid(context, &args.stateid, fh_fileid, Need::Read)?.ok_or_else(|| nfsstat4::NFS4ERR_BADHANDLE)?;

    debug!("OP_READ id={} fh={} offset={} count={}", fh_fileid, *vfs_fh, args.offset, args.count);

    require_reg(context, fh_fileid).await?;

    let (data, eof) = context.vfs.read(*vfs_fh, fh_fileid, args.offset, args.count).await?;
    let resok = READ4resok { eof, data };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_WRITE (RFC 8881 §18.32).
/// Writes to the current filehandle. Because the VFS write is synchronous
/// and durable, we always report FILE_SYNC4 (no COMMIT required).
async fn op_write(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = WRITE4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    let fh = state.current_fh()?;
    let fh_fileid = fh_to_id(context, fh)?;

    require_writable(context)?;
    let vfs_fh =
        check_stateid(context, &args.stateid, fh_fileid, Need::Write)?.ok_or_else(|| nfsstat4::NFS4ERR_BADHANDLE)?;
    require_reg(context, fh_fileid).await?;

    let write_len = args.data.len();
    debug!(
        "OP_WRITE id={} fh={} offset={} len={} stable={:?}",
        fh_fileid, *vfs_fh, args.offset, write_len, args.stable
    );

    context.vfs.write(*vfs_fh, fh_fileid, args.offset, &args.data).await?;

    let resok = WRITE4resok {
        count: write_len as count4,
        committed: stable_how4::FILE_SYNC4,
        writeverf: write_verifier(context.epoch),
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_REMOVE (RFC 8881 §18.25).
/// Removes `target` from the current directory FH. The VFS `remove`
/// handles both files and (empty) directories per its contract.
async fn op_remove(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = REMOVE4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    require_writable(context)?;
    if args.target.0.is_empty() {
        return Err(nfsstat4::NFS4ERR_INVAL.into());
    }

    let dir_fh = state.current_fh()?;
    let dirid = fh_to_id(context, dir_fh)?;
    let before = change_before(&require_dir(context, dirid).await?);

    let name: filename4 = args.target.0.clone().into();
    debug!("OP_REMOVE dir={} name={:?}", dirid, args.target);

    context.vfs.remove(dirid, &name).await?;
    let after = change_after(context, dirid, before).await;

    let resok = REMOVE4resok {
        cinfo: change_info4 {
            atomic: false,
            before,
            after,
        },
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_CREATE (RFC 8881 §18.4).
/// Creates a NON-regular object in the current directory FH. Regular files
/// are created via OPEN, not here. We support NF4DIR and NF4LNK; other
/// types return NFS4ERR_NOTSUPP (the VFS lacks mknod).
/// On success the current FH becomes the newly created object.
async fn op_create(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = CREATE4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    require_writable(context)?;
    if args.objname.0.is_empty() {
        return Err(nfsstat4::NFS4ERR_INVAL.into());
    }

    let dir_fh = state.current_fh()?;
    let dirid = fh_to_id(context, dir_fh)?;
    let before = change_before(&require_dir(context, dirid).await?);

    let name: filename4 = args.objname.0.clone().into();
    debug!("OP_CREATE dir={} name={:?} type={:?}", dirid, args.objname, args.objtype.ftype);

    let new_id: fileid4 = match args.objtype.ftype {
        ftype4::NF4DIR => context.vfs.mkdir(dirid, &name).await?.0,
        ftype4::NF4LNK => {
            let target: nfspath4 = args.objtype.linkdata.0.clone().into();
            let attr = crate::nfs3::sattr3::default();
            context.vfs.symlink(dirid, &name, &target, &attr).await?.0
        },
        _ => return Err(nfsstat4::NFS4ERR_NOTSUPP.into()),
    };

    state.current_fh = Some(id_to_fh(context.epoch, new_id));
    let after = change_after(context, dirid, before).await;

    let resok = CREATE4resok {
        cinfo: change_info4 {
            atomic: false,
            before,
            after,
        },
        attrset: Vec::new(),
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

async fn op_savefh(op_out: &mut impl Write, state: &mut CompoundState) -> Result<(), OpError> {
    state.require_session()?;
    let fh = state.current_fh()?.clone();
    state.saved_fh = Some(fh);
    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_RESTOREFH (RFC 8881 §18.27).
/// Copies the saved filehandle into the current filehandle.
async fn op_restorefh(op_out: &mut impl Write, state: &mut CompoundState) -> Result<(), OpError> {
    state.require_session()?;
    let fh = state.saved_fh.clone().ok_or(OpError::Status(nfsstat4::NFS4ERR_RESTOREFH))?;
    state.current_fh = Some(fh);
    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_RENAME (RFC 8881 §18.26).
/// Source dir = SAVED filehandle, target dir = CURRENT filehandle.
async fn op_rename(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = RENAME4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    require_writable(context)?;
    if args.oldname.0.is_empty() || args.newname.0.is_empty() {
        return Err(nfsstat4::NFS4ERR_INVAL.into());
    }

    let from_dirid = fh_to_id(context, state.saved_fh()?)?;
    let to_dirid = fh_to_id(context, state.current_fh()?)?;

    let src_before = change_before(&require_dir(context, from_dirid).await?);
    let tgt_before = change_before(&require_dir(context, to_dirid).await?);

    let oldname: filename4 = args.oldname.0.clone().into();
    let newname: filename4 = args.newname.0.clone().into();

    debug!(
        "OP_RENAME from_dir={} old={:?} to_dir={} new={:?}",
        from_dirid, args.oldname, to_dirid, args.newname
    );

    context.vfs.rename(from_dirid, &oldname, to_dirid, &newname).await?;

    let src_after = change_after(context, from_dirid, src_before).await;
    let tgt_after = change_after(context, to_dirid, tgt_before).await;

    let resok = RENAME4resok {
        source_cinfo: change_info4 {
            atomic: false,
            before: src_before,
            after: src_after,
        },
        target_cinfo: change_info4 {
            atomic: false,
            before: tgt_before,
            after: tgt_after,
        },
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_SETATTR (RFC 8881 §18.30).
/// Self-serializing: `attrsset` always follows the status, so this op emits
/// its own status + bitmap in every path and returns the status directly.
async fn op_setattr<R: Read, W: Write>(
    input: &mut R,
    op_out: &mut W,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<nfsstat4, anyhow::Error> {
    let mut stateid = stateid4::default();
    let mut attrs = fattr4::default();
    stateid.deserialize(input)?;
    attrs.deserialize(input)?;

    let empty = bitmap4::new();

    // Fallible core: returns the set bitmap on success, or a status to emit
    // (with an empty bitmap) on failure.
    let core = async {
        state.require_session()?;
        require_writable(context)?;

        let fileid = fh_to_id(context, state.current_fh()?)?;

        if attrs.size.is_some() {
            check_stateid(context, &stateid, fileid, Need::Write)?;
        }

        let (sattr, set_bits) = attrs
            .to_sattr3()
            .map_err(|_bit| OpError::Status(nfsstat4::NFS4ERR_ATTRNOTSUPP))?;

        debug!("OP_SETATTR id={} set_bits={:x?}", fileid, set_bits);

        context.vfs.setattr(fileid, sattr).await?;
        Ok::<bitmap4, OpError>(set_bits)
    };

    match core.await {
        Ok(set_bits) => {
            nfsstat4::NFS4_OK.serialize(op_out)?;
            set_bits.serialize(op_out)?;
            Ok(nfsstat4::NFS4_OK)
        },
        Err(OpError::Status(s)) => {
            s.serialize(op_out)?;
            empty.serialize(op_out)?;
            Ok(s)
        },
        Err(OpError::Fatal(e)) => Err(e),
    }
}

/// OP_READLINK (RFC 8881 §18.24).
/// Returns the target path of the symlink at the current FH.
async fn op_readlink(op_out: &mut impl Write, state: &mut CompoundState, context: &RPCContext) -> Result<(), OpError> {
    state.require_session()?;
    let fh = state.current_fh()?;
    let id = fh_to_id(context, fh)?;

    require_symlink(context, id).await?;

    debug!("OP_READLINK id={}", id);

    let target = context.vfs.readlink(id).await?;
    let resok = READLINK4resok { link: target };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_COMMIT (RFC 8881 §18.3).
/// Our WRITE always reports FILE_SYNC4 (data is durable on return), so
/// there is nothing to flush. We validate the current FH is a regular file
/// and return the stable write verifier.
async fn op_commit(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = COMMIT4args::default();
    args.deserialize(input)?;

    state.require_session()?;
    let fh = state.current_fh()?;
    let fileid = fh_to_id(context, fh)?;

    require_reg(context, fileid).await?;

    debug!("OP_COMMIT id={} offset={} count={}", fileid, args.offset, args.count);

    let resok = COMMIT4resok {
        writeverf: write_verifier(context.epoch),
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_TEST_STATEID (RFC 8881 §18.48).
/// Reports validity of each supplied stateid.
async fn op_test_stateid(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = TEST_STATEID4args::default();
    args.deserialize(input)?;

    state.require_session()?;

    debug!("OP_TEST_STATEID count={}", args.ts_stateids.len());
    let cid = context.client_id().ok_or_else(|| nfsstat4::NFS4ERR_BAD_STATEID)?;

    let codes: Vec<nfsstat4> = args
        .ts_stateids
        .iter()
        .map(|sid| context.nfs4_state.test_stateid(cid, sid))
        .collect();

    let resok = TEST_STATEID4resok {
        tsr_status_codes: codes,
    };

    // Overall op status is NFS4_OK; per-stateid results are in the array.
    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_SETCLIENTID (NFSv4.0, RFC 7530 §16.33).
/// Establishes an unconfirmed clientid. Callback data is decoded and ignored
/// (we grant no delegations, so we never call back).
async fn op_setclientid(input: &mut impl Read, op_out: &mut impl Write, context: &RPCContext) -> Result<(), OpError> {
    let mut args = SETCLIENTID4args::default();
    args.deserialize(input)?;

    debug!(
        "OP_SETCLIENTID id={:?} cb_prog={} netid={:?} addr={:?}",
        nfsstring::from(args.client.id.clone()),
        args.callback.cb_program,
        args.callback.cb_location.r_netid,
        args.callback.cb_location.r_addr,
    );

    let (clientid, verifier) = context.nfs4_state.setclientid(&args.client.id, &args.client.verifier);

    let resok = SETCLIENTID4resok {
        clientid,
        setclientid_confirm: verifier,
    };

    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_SETCLIENTID_CONFIRM (NFSv4.0, RFC 7530 §16.34).
async fn op_setclientid_confirm(
    input: &mut impl Read,
    op_out: &mut impl Write,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = SETCLIENTID_CONFIRM4args::default();
    args.deserialize(input)?;

    debug!("OP_SETCLIENTID_CONFIRM clientid={:#x}", args.clientid);

    context
        .nfs4_state
        .setclientid_confirm(args.clientid, &args.setclientid_confirm)?;
    context.set_client_id(args.clientid);
    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_RENEW (NFSv4.0, RFC 7530 §16.30).
async fn op_renew(input: &mut impl Read, op_out: &mut impl Write, context: &RPCContext) -> Result<(), OpError> {
    let mut args = RENEW4args::default();
    args.deserialize(input)?;

    debug!("OP_RENEW clientid={:#x}", args.clientid);

    context.nfs4_state.renew(args.clientid)?;
    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}

/// OP_OPEN_CONFIRM (NFSv4.0, RFC 7530 §16.18).
/// Confirms the open owner established by a preceding OPEN with
/// OPEN4_RESULT_CONFIRM set.
async fn op_open_confirm(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = OPEN_CONFIRM4args::default();
    args.deserialize(input)?;

    state.current_fh()?; // require FH

    debug!("OP_OPEN_CONFIRM seqid={} stateid.other={:x?}", args.seqid, args.open_stateid.other);
    let cid = context.client_id().ok_or_else(|| nfsstat4::NFS4ERR_BAD_STATEID)?;
    let stateid = context.nfs4_state.open_confirm(cid, &args.open_stateid, args.seqid)?;
    let resok = OPEN_CONFIRM4resok { open_stateid: stateid };
    nfsstat4::NFS4_OK.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(())
}

/// OP_RELEASE_LOCKOWNER (NFSv4.0, RFC 7530 §16.37).
/// We do not support locking, so there are never any locks held for an owner.
/// Acknowledge unconditionally.
async fn op_release_lockowner(
    input: &mut impl Read,
    op_out: &mut impl Write,
    _context: &RPCContext,
) -> Result<(), OpError> {
    let mut args = RELEASE_LOCKOWNER4args::default();
    args.deserialize(input)?;

    debug!("OP_RELEASE_LOCKOWNER clientid={:#x}", args.lock_owner.clientid);

    nfsstat4::NFS4_OK.serialize(op_out)?;
    Ok(())
}
