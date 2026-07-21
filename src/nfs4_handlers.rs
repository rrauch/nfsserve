#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::io::{Cursor, Read, Write};

use num_traits::cast::FromPrimitive;
use tracing::{debug, warn};

use crate::context::RPCContext;
use crate::nfs4::*;
use crate::rpc::*;
use crate::xdr::*;

/// Per-COMPOUND execution state.
struct CompoundState {
    opcount: usize,
}

impl CompoundState {
    fn new() -> Self {
        Self { opcount: 0 }
    }
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

        let status = match nfs_opnum4::from_u32(opnum_raw) {
            Some(op) => dispatch_op(op, input, &mut op_out, &mut state, context).await?,
            None => {
                // Unknown/unsupported op: must consume nothing more safely.
                // We cannot skip args we don't understand, so we must abort.
                // Encode OP_ILLEGAL semantics.
                warn!("nfs4: illegal/unknown opnum {}", opnum_raw);
                nfsstat4::NFS4ERR_OP_ILLEGAL.serialize(&mut op_out)?;
                nfsstat4::NFS4ERR_OP_ILLEGAL
            },
        };

        rescount += 1;
        result_buf.extend_from_slice(&op_out.into_inner());
        last_status = status;
        state.opcount += 1;

        // COMPOUND stops at first error
        if status != nfsstat4::NFS4_OK {
            break;
        }
    }

    // ---- emit COMPOUND4res ----
    make_success_reply(xid).serialize(output)?;
    last_status.serialize(output)?;
    tag.serialize(output)?;
    rescount.serialize(output)?;
    output.write_all(&result_buf)?;
    Ok(())
}

/// Dispatch a single op. The op body has already had its opnum consumed
/// from `input` and echoed into `op_out`. Each arm must:
///   - decode its args from `input`
///   - write its result status + result body into `op_out`
///   - return the nfsstat4 status
async fn dispatch_op(
    op: nfs_opnum4,
    input: &mut impl Read,
    op_out: &mut impl Write,
    state: &mut CompoundState,
    context: &RPCContext,
) -> Result<nfsstat4, anyhow::Error> {
    use nfs_opnum4::*;
    match op {
        other => {
            warn!("nfs4: unimplemented op {:?}", other);
            // NOTE: we have NOT decoded this op's args, so the input
            // stream is now misaligned. Returning here is only safe if
            // this is the LAST op or the client sent it standalone.
            // For a skeleton this is acceptable; fill in ops before use.
            nfsstat4::NFS4ERR_NOTSUPP.serialize(op_out)?;
            Ok(nfsstat4::NFS4ERR_NOTSUPP)
        },
    }
}
