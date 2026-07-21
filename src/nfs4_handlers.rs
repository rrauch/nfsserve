#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::io::{Cursor, Read, Write};

use num_traits::cast::FromPrimitive;
use tracing::{debug, warn};

use crate::context::RPCContext;
use crate::nfs::nfsstring;
use crate::nfs4::*;
use crate::rpc::*;
use crate::xdr::*;

/// Per-COMPOUND execution state.
struct CompoundState {
    // Current / saved filehandle (RFC 8881 §16.2). Ops like PUTFH/GETFH/
    // LOOKUP operate on these. None => NFS4ERR_NOFILEHANDLE.
    current_fh: Option<nfs_fh4>,
    saved_fh: Option<nfs_fh4>,

    // Set once SEQUENCE runs. Binds this compound to a session + slot.
    // None until SEQUENCE succeeds; most ops require it (else
    // NFS4ERR_OP_NOT_IN_SESSION for the first non-SEQUENCE op).
    session: Option<SequenceContext>,
    opcount: usize,
}

impl CompoundState {
    fn new() -> Self {
        Self {
            current_fh: None,
            saved_fh: None,
            session: None,
            opcount: 0,
        }
    }
}

struct SequenceContext {
    sessionid: sessionid4,
    slotid: slotid4,
    sequenceid: sequenceid4,
    cache_this: bool,
}

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
    // ---- decode COMPOUND4args header ----
    let mut tag = crate::nfs::nfsstring::default();
    tag.deserialize(input)?;
    let mut minorversion: u32 = 0;
    minorversion.deserialize(input)?;
    let mut num_ops: u32 = 0;
    num_ops.deserialize(input)?;

    debug!("nfs4 COMPOUND xid={} tag={:?} minor={} nops={}", xid, tag, minorversion, num_ops);

    // Reject anything but 4.1
    if minorversion != 1 {
        make_success_reply(xid).serialize(output)?;
        nfsstat4::NFS4ERR_MINOR_VERS_MISMATCH.serialize(output)?;
        tag.serialize(output)?;
        0u32.serialize(output)?; // empty resarray
        return Ok(());
    }

    let mut state = CompoundState::new();
    let mut result_buf: Vec<u8> = Vec::new();
    let mut rescount: u32 = 0;
    let mut last_status = nfsstat4::NFS4_OK;

    for _ in 0..num_ops {
        // each nfs_argop4 begins with the opnum
        let mut opnum_raw: u32 = 0;
        opnum_raw.deserialize(input)?;

        let mut op_out = Cursor::new(Vec::<u8>::new());
        // echo the opnum into the result (nfs_resop4 also starts with opnum)
        opnum_raw.serialize(&mut op_out)?;

        let dispatch = match nfs_opnum4::from_u32(opnum_raw) {
            Some(op) => dispatch_op(op, input, &mut op_out, &mut state, context).await?,
            None => {
                warn!("nfs4: illegal/unknown opnum {}", opnum_raw);
                // Re-encode as OP_ILLEGAL result.
                let mut illegal = Cursor::new(Vec::<u8>::new());
                nfs_opnum4::OP_ILLEGAL.serialize(&mut illegal)?;
                nfsstat4::NFS4ERR_OP_ILLEGAL.serialize(&mut illegal)?;
                op_out = illegal;
                DispatchResult::Status(nfsstat4::NFS4ERR_OP_ILLEGAL)
            },
        };

        // Handle SEQUENCE replay: abort normal assembly, emit cached bytes.
        if let DispatchResult::Replay(cached) = dispatch {
            // The cached bytes are a full COMPOUND4res body
            // (status + tag + resarray). Emit verbatim.
            make_success_reply(xid).serialize(output)?;
            output.write_all(&cached)?;
            return Ok(());
        }

        let status = dispatch.status();

        rescount += 1;
        result_buf.extend_from_slice(&op_out.into_inner());
        last_status = status;
        state.opcount += 1;

        // COMPOUND stops at first error
        if status != nfsstat4::NFS4_OK {
            break;
        }
    }

    // Assemble the full COMPOUND4res body.
    let mut body: Vec<u8> = Vec::new();
    last_status.serialize(&mut body)?;
    tag.serialize(&mut body)?;
    rescount.serialize(&mut body)?;
    body.extend_from_slice(&result_buf);

    // If this compound ran under SEQUENCE with sa_cachethis, cache the body.
    if let Some(seq) = &state.session {
        if seq.cache_this {
            context
                .nfs4_state
                .cache_reply(&seq.sessionid, seq.slotid, seq.sequenceid, body.clone());
        }
    }

    make_success_reply(xid).serialize(output)?;
    output.write_all(&body)?;
    Ok(())
}

enum DispatchResult {
    Status(nfsstat4),
    /// SEQUENCE detected a replay; carries the cached COMPOUND4res body.
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
    match op {
        OP_EXCHANGE_ID => op_exchange_id(input, op_out, context).await.map(DispatchResult::Status),
        OP_CREATE_SESSION => op_create_session(input, op_out, context).await.map(DispatchResult::Status),
        OP_DESTROY_SESSION => op_destroy_session(input, op_out, state, context)
            .await
            .map(DispatchResult::Status),
        OP_DESTROY_CLIENTID => op_destroy_clientid(input, op_out, context).await.map(DispatchResult::Status),
        OP_SEQUENCE => op_sequence(input, op_out, state, context).await,
        other => {
            warn!("nfs4: unimplemented op {:?}", other);
            // NOTE: we have NOT decoded this op's args, so the input
            // stream is now misaligned. Returning here is only safe if
            // this is the LAST op or the client sent it standalone.
            // For a skeleton this is acceptable; fill in ops before use.
            nfsstat4::NFS4ERR_NOTSUPP.serialize(op_out)?;
            Ok(DispatchResult::Status(nfsstat4::NFS4ERR_NOTSUPP))
        },
    }
}

/// OP_EXCHANGE_ID (RFC 8881 §18.35).
/// SP4_NONE only, non-pNFS
async fn op_exchange_id(
    input: &mut impl Read,
    op_out: &mut impl Write,
    context: &RPCContext,
) -> Result<nfsstat4, anyhow::Error> {
    let mut args = EXCHANGE_ID4args::default();
    args.deserialize(input)?;

    debug!(
        "OP_EXCHANGE_ID owner={:?} flags={:#x} how={:?}",
        nfsstring::from(args.eia_clientowner.co_ownerid.clone()),
        args.eia_flags,
        args.eia_state_protect.spa_how
    );

    // We only support SP4_NONE.
    if args.eia_state_protect.spa_how != state_protect_how4::SP4_NONE {
        nfsstat4::NFS4ERR_NOTSUPP.serialize(op_out)?;
        return Ok(nfsstat4::NFS4ERR_NOTSUPP);
    }

    let res = context
        .nfs4_state
        .exchange_id(&args.eia_clientowner.co_ownerid, &args.eia_clientowner.co_verifier);

    let resok = EXCHANGE_ID4resok {
        eir_clientid: res.clientid,
        eir_sequenceid: res.seqid,
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
    Ok(nfsstat4::NFS4_OK)
}

/// OP_CREATE_SESSION (RFC 8881 §18.36).
/// Lean impl: single-slot fore channel, no back channel, no persistence.
async fn op_create_session(
    input: &mut impl Read,
    op_out: &mut impl Write,
    context: &RPCContext,
) -> Result<nfsstat4, anyhow::Error> {
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

    // Negotiate fore channel: clamp to our minimal capabilities.
    // Single slot => ca_maxrequests = 1. Reply cache size must accommodate
    // one cached reply per slot.
    const MAX_REQUEST_SIZE: u32 = 1 << 20; // 1 MiB
    const MAX_RESPONSE_SIZE: u32 = 1 << 20;
    const MAX_OPS: u32 = 8;
    const MAX_REQUESTS: u32 = 1;

    let fore = channel_attrs4 {
        ca_headerpadsize: 0,
        ca_maxrequestsize: args.csa_fore_chan_attrs.ca_maxrequestsize.min(MAX_REQUEST_SIZE),
        ca_maxresponsesize: args.csa_fore_chan_attrs.ca_maxresponsesize.min(MAX_RESPONSE_SIZE),
        ca_maxresponsesize_cached: args.csa_fore_chan_attrs.ca_maxresponsesize_cached.min(MAX_RESPONSE_SIZE),
        ca_maxoperations: args.csa_fore_chan_attrs.ca_maxoperations.min(MAX_OPS).max(1),
        ca_maxrequests: args.csa_fore_chan_attrs.ca_maxrequests.min(MAX_REQUESTS).max(1),
        ca_rdma_ird: Vec::new(),
    };

    // Back channel: we grant no delegations/callbacks. Advertise a
    // degenerate back channel and clear CONN_BACK_CHAN in csr_flags.
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

    use crate::nfs4_state::CreateSessionOutcome::*;
    let (sessionid, status) = match context.nfs4_state.create_session(
        args.csa_clientid,
        args.csa_sequence,
        num_slots,
        fore.clone(),
        back.clone(),
    ) {
        Ok { sessionid } => (sessionid, nfsstat4::NFS4_OK),
        Replay { sessionid } => (sessionid, nfsstat4::NFS4_OK),
        StaleClientId => {
            nfsstat4::NFS4ERR_STALE_CLIENTID.serialize(op_out)?;
            return Ok(nfsstat4::NFS4ERR_STALE_CLIENTID);
        },
        SeqMisordered => {
            nfsstat4::NFS4ERR_SEQ_MISORDERED.serialize(op_out)?;
            return Ok(nfsstat4::NFS4ERR_SEQ_MISORDERED);
        },
    };

    let resok = CREATE_SESSION4resok {
        csr_sessionid: sessionid,
        csr_sequence: args.csa_sequence,
        csr_flags: 0, // no PERSIST, no CONN_BACK_CHAN, no RDMA
        csr_fore_chan_attrs: fore,
        csr_back_chan_attrs: back,
    };

    status.serialize(op_out)?;
    resok.serialize(op_out)?;
    Ok(status)
}

/// OP_DESTROY_SESSION (RFC 8881 §18.37).
async fn op_destroy_session(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<nfsstat4, anyhow::Error> {
    let mut args = DESTROY_SESSION4args::default();
    args.deserialize(input)?;

    debug!("OP_DESTROY_SESSION sessionid={:x?}", args.dsa_sessionid);

    let destroying_current = state
        .session
        .as_ref()
        .map(|s| s.sessionid == args.dsa_sessionid)
        .unwrap_or(false);

    if destroying_current {
        // Prevent the compound loop from caching into a now-dead slot.
        state.session = None;
    }

    let ok = context.nfs4_state.destroy_session(&args.dsa_sessionid);
    let status = if ok {
        nfsstat4::NFS4_OK
    } else {
        nfsstat4::NFS4ERR_BADSESSION
    };

    status.serialize(op_out)?;
    Ok(status)
}

/// OP_DESTROY_CLIENTID (RFC 8881 §18.50).
async fn op_destroy_clientid(
    input: &mut impl Read,
    op_out: &mut impl Write,
    context: &RPCContext,
) -> Result<nfsstat4, anyhow::Error> {
    let mut args = DESTROY_CLIENTID4args::default();
    args.deserialize(input)?;

    debug!("OP_DESTROY_CLIENTID clientid={:#x}", args.dca_clientid);

    use crate::nfs4_state::DestroyClientIdOutcome;
    let status = match context.nfs4_state.destroy_clientid(args.dca_clientid) {
        DestroyClientIdOutcome::Ok => nfsstat4::NFS4_OK,
        DestroyClientIdOutcome::StaleClientId => nfsstat4::NFS4ERR_STALE_CLIENTID,
        DestroyClientIdOutcome::Busy => nfsstat4::NFS4ERR_CLIENTID_BUSY,
    };

    status.serialize(op_out)?;
    Ok(status)
}

/// OP_SEQUENCE (RFC 8881 §18.46).
/// Must be the first op in the compound. Establishes session binding,
/// enforces exactly-once semantics via the per-slot reply cache, and
/// implicitly renews the lease.
async fn op_sequence(
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<DispatchResult, anyhow::Error> {
    let mut args = SEQUENCE4args::default();
    args.deserialize(input)?;

    debug!(
        "OP_SEQUENCE session={:x?} seq={} slot={} high={} cache={}",
        args.sa_sessionid, args.sa_sequenceid, args.sa_slotid, args.sa_highest_slotid, args.sa_cachethis
    );

    // SEQUENCE must be first (NFS4ERR_SEQUENCE_POS).
    if state.opcount != 0 {
        nfsstat4::NFS4ERR_SEQUENCE_POS.serialize(op_out)?;
        return Ok(DispatchResult::Status(nfsstat4::NFS4ERR_SEQUENCE_POS));
    }

    use crate::nfs4_state::SequenceOutcome::*;
    let status = match context
        .nfs4_state
        .sequence_check(&args.sa_sessionid, args.sa_slotid, args.sa_sequenceid)
    {
        New => nfsstat4::NFS4_OK,
        Replay(cached) => {
            // Signal the compound loop to emit the cached reply verbatim.
            return Ok(DispatchResult::Replay(cached));
        },
        RetryUncached => nfsstat4::NFS4ERR_RETRY_UNCACHED_REP,
        Misordered => nfsstat4::NFS4ERR_SEQ_MISORDERED,
        BadSession => nfsstat4::NFS4ERR_BADSESSION,
        BadSlot => nfsstat4::NFS4ERR_BADSLOT,
    };

    if status != nfsstat4::NFS4_OK {
        status.serialize(op_out)?;
        return Ok(DispatchResult::Status(status));
    }

    // Bind session context for reply caching + later ops.
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
