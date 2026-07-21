#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::nfs::{nfs_fh, nfsstring, opaque, specdata};
use crate::xdr::*;
use crate::{xdr_enum_serde, xdr_struct};

use crate::nfs3::{fattr3, ftype3, nfsstat3, nfstime3};

use byteorder::{ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;
use std::io::{Read, Write};

// ---- RPC identity ----
pub const VERSION: u32 = 4;

// ---- Sizes ----
pub const NFS4_FHSIZE: u32 = 128;
pub const NFS4_VERIFIER_SIZE: usize = 8;
pub const NFS4_OTHER_SIZE: usize = 12;
pub const NFS4_SESSIONID_SIZE: usize = 16;
pub const NFS4_LEASE_TIME: u32 = 90;

// ---- Basic type aliases ----
pub type nfs_fh4 = nfs_fh;
pub type fileid4 = u64;
pub type offset4 = u64;
pub type length4 = u64;
pub type count4 = u32;
pub type mode4 = u32;
pub type qop4 = u32;
pub type sequenceid4 = u32;
pub type clientid4 = u64;
pub type seqid4 = u32;
pub type slotid4 = u32;
pub type verifier4 = [opaque; NFS4_VERIFIER_SIZE];
pub type sessionid4 = [opaque; NFS4_SESSIONID_SIZE];
pub type bitmap4 = Vec<u32>;
pub type utf8str_cs = nfsstring;
pub type utf8str_cis = nfsstring;
pub type utf8str_mixed = nfsstring;
pub type component4 = nfsstring;
pub type linktext4 = nfsstring;
pub type attrlist4 = Vec<u8>;
pub type nfs_lease4 = u32;
pub type changeid4 = u64;
pub type secret4 = Vec<u8>;

/// nfsstat4 as defined in RFC 8881 §13.1.
#[derive(Copy, Clone, Debug, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum nfsstat4 {
    NFS4_OK = 0,
    NFS4ERR_PERM = 1,
    NFS4ERR_NOENT = 2,
    NFS4ERR_IO = 5,
    NFS4ERR_NXIO = 6,
    NFS4ERR_ACCESS = 13,
    NFS4ERR_EXIST = 17,
    NFS4ERR_XDEV = 18,
    NFS4ERR_NOTDIR = 20,
    NFS4ERR_ISDIR = 21,
    NFS4ERR_INVAL = 22,
    NFS4ERR_FBIG = 27,
    NFS4ERR_NOSPC = 28,
    NFS4ERR_ROFS = 30,
    NFS4ERR_MLINK = 31,
    NFS4ERR_NAMETOOLONG = 63,
    NFS4ERR_NOTEMPTY = 66,
    NFS4ERR_DQUOT = 69,
    NFS4ERR_STALE = 70,
    NFS4ERR_BADHANDLE = 10001,
    NFS4ERR_BAD_COOKIE = 10003,
    NFS4ERR_NOTSUPP = 10004,
    NFS4ERR_TOOSMALL = 10005,
    NFS4ERR_SERVERFAULT = 10006,
    NFS4ERR_BADTYPE = 10007,
    NFS4ERR_DELAY = 10008,
    NFS4ERR_SAME = 10009,
    NFS4ERR_DENIED = 10010,
    NFS4ERR_EXPIRED = 10011,
    NFS4ERR_LOCKED = 10012,
    NFS4ERR_GRACE = 10013,
    NFS4ERR_FHEXPIRED = 10014,
    NFS4ERR_SHARE_DENIED = 10015,
    NFS4ERR_WRONGSEC = 10016,
    NFS4ERR_CLID_INUSE = 10017,
    NFS4ERR_RESOURCE = 10018,
    NFS4ERR_MOVED = 10019,
    NFS4ERR_NOFILEHANDLE = 10020,
    NFS4ERR_MINOR_VERS_MISMATCH = 10021,
    NFS4ERR_STALE_CLIENTID = 10022,
    NFS4ERR_STALE_STATEID = 10023,
    NFS4ERR_OLD_STATEID = 10024,
    NFS4ERR_BAD_STATEID = 10025,
    NFS4ERR_BAD_SEQID = 10026,
    NFS4ERR_NOT_SAME = 10027,
    NFS4ERR_LOCK_RANGE = 10028,
    NFS4ERR_SYMLINK = 10029,
    NFS4ERR_RESTOREFH = 10030,
    NFS4ERR_LEASE_MOVED = 10031,
    NFS4ERR_ATTRNOTSUPP = 10032,
    NFS4ERR_NO_GRACE = 10033,
    NFS4ERR_RECLAIM_BAD = 10034,
    NFS4ERR_RECLAIM_CONFLICT = 10035,
    NFS4ERR_BADXDR = 10036,
    NFS4ERR_LOCKS_HELD = 10037,
    NFS4ERR_OPENMODE = 10038,
    NFS4ERR_BADOWNER = 10039,
    NFS4ERR_BADCHAR = 10040,
    NFS4ERR_BADNAME = 10041,
    NFS4ERR_BAD_RANGE = 10042,
    NFS4ERR_LOCK_NOTSUPP = 10043,
    NFS4ERR_OP_ILLEGAL = 10044,
    NFS4ERR_DEADLOCK = 10045,
    NFS4ERR_FILE_OPEN = 10046,
    NFS4ERR_ADMIN_REVOKED = 10047,
    NFS4ERR_CB_PATH_DOWN = 10048,
    // ---- NFSv4.1 (RFC 8881 §13.1.1) ----
    NFS4ERR_BADIOMODE = 10049,
    NFS4ERR_BADLAYOUT = 10050,
    NFS4ERR_BAD_SESSION_DIGEST = 10051,
    NFS4ERR_BADSESSION = 10052,
    NFS4ERR_BADSLOT = 10053,
    NFS4ERR_COMPLETE_ALREADY = 10054,
    NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055,
    NFS4ERR_DELEG_ALREADY_WANTED = 10056,
    NFS4ERR_BACK_CHAN_BUSY = 10057,
    NFS4ERR_LAYOUTTRYLATER = 10058,
    NFS4ERR_LAYOUTUNAVAILABLE = 10059,
    NFS4ERR_NOMATCHING_LAYOUT = 10060,
    NFS4ERR_RECALLCONFLICT = 10061,
    NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062,
    NFS4ERR_SEQ_MISORDERED = 10063,
    NFS4ERR_SEQUENCE_POS = 10064,
    NFS4ERR_REQ_TOO_BIG = 10065,
    NFS4ERR_REP_TOO_BIG = 10066,
    NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067,
    NFS4ERR_RETRY_UNCACHED_REP = 10068,
    NFS4ERR_UNSAFE_COMPOUND = 10069,
    NFS4ERR_TOO_MANY_OPS = 10070,
    NFS4ERR_OP_NOT_IN_SESSION = 10071,
    NFS4ERR_HASH_ALG_UNSUPP = 10072,
    NFS4ERR_CLIENTID_BUSY = 10074,
    NFS4ERR_PNFS_IO_HOLE = 10075,
    NFS4ERR_SEQ_FALSE_RETRY = 10076,
    NFS4ERR_BAD_HIGH_SLOT = 10077,
    NFS4ERR_DEADSESSION = 10078,
    NFS4ERR_ENCR_ALG_UNSUPP = 10079,
    NFS4ERR_PNFS_NO_LAYOUT = 10080,
    NFS4ERR_NOT_ONLY_OP = 10081,
    NFS4ERR_WRONG_CRED = 10082,
    NFS4ERR_WRONG_TYPE = 10083,
    NFS4ERR_DIRDELEG_UNAVAIL = 10084,
    NFS4ERR_REJECT_DELEG = 10085,
    NFS4ERR_RETURNCONFLICT = 10086,
    NFS4ERR_DELEG_REVOKED = 10087,
    // -- not part of RFC --
    ILLEGAL = u32::MAX,
}
xdr_enum_serde!(nfsstat4);

impl Default for nfsstat4 {
    fn default() -> Self {
        Self::ILLEGAL
    }
}

impl From<nfsstat3> for nfsstat4 {
    fn from(e: nfsstat3) -> Self {
        match e {
            nfsstat3::NFS3_OK => nfsstat4::NFS4_OK,
            nfsstat3::NFS3ERR_PERM => nfsstat4::NFS4ERR_PERM,
            nfsstat3::NFS3ERR_NOENT => nfsstat4::NFS4ERR_NOENT,
            nfsstat3::NFS3ERR_IO => nfsstat4::NFS4ERR_IO,
            nfsstat3::NFS3ERR_NXIO => nfsstat4::NFS4ERR_NXIO,
            nfsstat3::NFS3ERR_ACCES => nfsstat4::NFS4ERR_ACCESS,
            nfsstat3::NFS3ERR_EXIST => nfsstat4::NFS4ERR_EXIST,
            nfsstat3::NFS3ERR_XDEV => nfsstat4::NFS4ERR_XDEV,
            nfsstat3::NFS3ERR_NOTDIR => nfsstat4::NFS4ERR_NOTDIR,
            nfsstat3::NFS3ERR_ISDIR => nfsstat4::NFS4ERR_ISDIR,
            nfsstat3::NFS3ERR_INVAL => nfsstat4::NFS4ERR_INVAL,
            nfsstat3::NFS3ERR_FBIG => nfsstat4::NFS4ERR_FBIG,
            nfsstat3::NFS3ERR_NOSPC => nfsstat4::NFS4ERR_NOSPC,
            nfsstat3::NFS3ERR_ROFS => nfsstat4::NFS4ERR_ROFS,
            nfsstat3::NFS3ERR_MLINK => nfsstat4::NFS4ERR_MLINK,
            nfsstat3::NFS3ERR_NAMETOOLONG => nfsstat4::NFS4ERR_NAMETOOLONG,
            nfsstat3::NFS3ERR_NOTEMPTY => nfsstat4::NFS4ERR_NOTEMPTY,
            nfsstat3::NFS3ERR_DQUOT => nfsstat4::NFS4ERR_DQUOT,
            nfsstat3::NFS3ERR_STALE => nfsstat4::NFS4ERR_STALE,
            nfsstat3::NFS3ERR_BADHANDLE => nfsstat4::NFS4ERR_BADHANDLE,
            nfsstat3::NFS3ERR_NOTSUPP => nfsstat4::NFS4ERR_NOTSUPP,
            nfsstat3::NFS3ERR_SERVERFAULT => nfsstat4::NFS4ERR_SERVERFAULT,
            nfsstat3::NFS3ERR_BADTYPE => nfsstat4::NFS4ERR_BADTYPE,
            nfsstat3::NFS3ERR_JUKEBOX => nfsstat4::NFS4ERR_DELAY,
            _ => nfsstat4::NFS4ERR_SERVERFAULT,
        }
    }
}

/// NFSv4 file type (RFC 8881 §5.8.1.1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum ftype4 {
    /// Regular file
    #[default]
    NF4REG = 1,
    /// Directory
    NF4DIR = 2,
    /// Block special device
    NF4BLK = 3,
    /// Character special device
    NF4CHR = 4,
    /// Symbolic link
    NF4LNK = 5,
    /// Socket
    NF4SOCK = 6,
    /// Named pipe
    NF4FIFO = 7,
    /// Attribute directory
    NF4ATTRDIR = 8,
    /// Named attribute
    NF4NAMEDATTR = 9,
}
xdr_enum_serde!(ftype4);

impl From<ftype3> for ftype4 {
    fn from(t: ftype3) -> Self {
        match t {
            ftype3::NF3REG => ftype4::NF4REG,
            ftype3::NF3DIR => ftype4::NF4DIR,
            ftype3::NF3BLK => ftype4::NF4BLK,
            ftype3::NF3CHR => ftype4::NF4CHR,
            ftype3::NF3LNK => ftype4::NF4LNK,
            ftype3::NF3SOCK => ftype4::NF4SOCK,
            ftype3::NF3FIFO => ftype4::NF4FIFO,
        }
    }
}

/// NFSv4.1 operation codes as defined in RFC 8881 (obsoletes RFC 5661).
///
/// NFSv4.0-only operations are intentionally absent: OP_OPEN_CONFIRM (20),
/// OP_RENEW (30), OP_SETCLIENTID (35), OP_SETCLIENTID_CONFIRM (36), and
/// OP_RELEASE_LOCKOWNER (39). Their function is subsumed by session-based
/// operations, so `from_u32` yields `None` for those opcodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum nfs_opnum4 {
    /// Check access rights to a file object (RFC 8881 §18.1).
    OP_ACCESS = 3,
    /// Close an open file, releasing share reservations (RFC 8881 §18.2).
    OP_CLOSE = 4,
    /// Commit cached/unstable writes to stable storage (RFC 8881 §18.3).
    OP_COMMIT = 5,
    /// Create a non-regular file object in a directory (RFC 8881 §18.4).
    OP_CREATE = 6,
    /// Purge all delegations awaiting recovery for a client (RFC 8881 §18.5).
    OP_DELEGPURGE = 7,
    /// Return a delegation to the server (RFC 8881 §18.6).
    OP_DELEGRETURN = 8,
    /// Retrieve attributes for the current filehandle (RFC 8881 §18.7).
    OP_GETATTR = 9,
    /// Get the current filehandle (RFC 8881 §18.8).
    OP_GETFH = 10,
    /// Create a hard link to an existing file object (RFC 8881 §18.9).
    OP_LINK = 11,
    /// Acquire a byte-range record lock (RFC 8881 §18.10).
    OP_LOCK = 12,
    /// Test for the existence of a conflicting lock (RFC 8881 §18.11).
    OP_LOCKT = 13,
    /// Unlock a byte-range record lock (RFC 8881 §18.12).
    OP_LOCKU = 14,
    /// Look up a filename in a directory (RFC 8881 §18.13).
    OP_LOOKUP = 15,
    /// Look up the parent directory (RFC 8881 §18.14).
    OP_LOOKUPP = 16,
    /// Verify that attributes do not match (RFC 8881 §18.15).
    OP_NVERIFY = 17,
    /// Open a regular file, establishing share reservations (RFC 8881 §18.16).
    OP_OPEN = 18,
    /// Open the named-attribute directory for an object (RFC 8881 §18.17).
    OP_OPENATTR = 19,
    /// Reduce the access/deny modes of an open file (RFC 8881 §18.18).
    OP_OPEN_DOWNGRADE = 21,
    /// Set the current filehandle to a supplied value (RFC 8881 §18.19).
    OP_PUTFH = 22,
    /// Set the current filehandle to the public filehandle (RFC 8881 §18.20).
    OP_PUTPUBFH = 23,
    /// Set the current filehandle to the root filehandle (RFC 8881 §18.21).
    OP_PUTROOTFH = 24,
    /// Read data from a regular file (RFC 8881 §18.22).
    OP_READ = 25,
    /// Read entries from a directory (RFC 8881 §18.23).
    OP_READDIR = 26,
    /// Read the target of a symbolic link (RFC 8881 §18.24).
    OP_READLINK = 27,
    /// Remove a file object from a directory (RFC 8881 §18.25).
    OP_REMOVE = 28,
    /// Rename a file object within/between directories (RFC 8881 §18.26).
    OP_RENAME = 29,
    /// Restore the saved filehandle as the current filehandle (RFC 8881 §18.27).
    OP_RESTOREFH = 31,
    /// Save the current filehandle for later restore (RFC 8881 §18.28).
    OP_SAVEFH = 32,
    /// Obtain security mechanisms for a directory entry (RFC 8881 §18.29).
    OP_SECINFO = 33,
    /// Set attributes on the current filehandle (RFC 8881 §18.30).
    OP_SETATTR = 34,
    /// Verify that attributes match supplied values (RFC 8881 §18.31).
    OP_VERIFY = 37,
    /// Write data to a regular file (RFC 8881 §18.32).
    OP_WRITE = 38,
    /// Backchannel control: adjust callback channel parameters (RFC 8881 §18.33).
    OP_BACKCHANNEL_CTL = 40,
    /// Associate an additional connection with a session (RFC 8881 §18.34).
    OP_BIND_CONN_TO_SESSION = 41,
    /// Exchange client identity and capabilities; establishes a clientid (RFC 8881 §18.35).
    OP_EXCHANGE_ID = 42,
    /// Create a session between client and server (RFC 8881 §18.36).
    OP_CREATE_SESSION = 43,
    /// Destroy a session (RFC 8881 §18.37).
    OP_DESTROY_SESSION = 44,
    /// Free a stateid that is no longer needed (RFC 8881 §18.38).
    OP_FREE_STATEID = 45,
    /// Request a directory delegation (RFC 8881 §18.39).
    OP_GET_DIR_DELEGATION = 46,
    /// pNFS: retrieve device addressing information (RFC 8881 §18.40).
    OP_GETDEVICEINFO = 47,
    /// pNFS: retrieve a list of device IDs (RFC 8881 §18.41).
    OP_GETDEVICELIST = 48,
    /// pNFS: commit data written via layouts to stable storage (RFC 8881 §18.42).
    OP_LAYOUTCOMMIT = 49,
    /// pNFS: obtain a layout for a file (RFC 8881 §18.43).
    OP_LAYOUTGET = 50,
    /// pNFS: return a previously granted layout (RFC 8881 §18.44).
    OP_LAYOUTRETURN = 51,
    /// Obtain security mechanisms by filename (no current FH change) (RFC 8881 §18.45).
    OP_SECINFO_NO_NAME = 52,
    /// Establish per-session request sequencing and exactly-once semantics (RFC 8881 §18.46).
    OP_SEQUENCE = 53,
    /// Set the SSV (secret session verifier) for SP4_SSV state protection (RFC 8881 §18.47).
    OP_SET_SSV = 54,
    /// Test whether one or more stateids are valid (RFC 8881 §18.48).
    OP_TEST_STATEID = 55,
    /// Want a delegation for a file, expressing desired type (RFC 8881 §18.49).
    OP_WANT_DELEGATION = 56,
    /// Destroy a clientid and all associated state (RFC 8881 §18.50).
    OP_DESTROY_CLIENTID = 57,
    /// Signal completion of state reclaim after server restart (RFC 8881 §18.51).
    OP_RECLAIM_COMPLETE = 58,
    /// Placeholder for an illegal operation; always returns NFS4ERR_OP_ILLEGAL (RFC 8881 §18.52).
    OP_ILLEGAL = 10044,
}
xdr_enum_serde!(nfs_opnum4);

// FATTR4
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct fattr4 {
    pub supported_attrs: Option<bitmap4>, // bit 0
    pub ftype: Option<ftype4>,            // bit 1
    pub fh_expire_type: Option<u32>,      // bit 2
    pub change: Option<changeid4>,        // bit 3
    pub size: Option<u64>,                // bit 4
    pub link_support: Option<bool>,       // bit 5
    pub symlink_support: Option<bool>,    // bit 6
    pub named_attr: Option<bool>,         // bit 7
    pub fsid: Option<fsid4>,              // bit 8
    pub unique_handles: Option<bool>,     // bit 9
    pub lease_time: Option<u32>,          // bit 10
    pub rdattr_error: Option<nfsstat4>,   // bit 11
    pub filehandle: Option<nfs_fh4>,      // bit 19

    pub acl: Option<Vec<nfsace4>>,       // bit 12
    pub aclsupport: Option<u32>,         // bit 13
    pub archive: Option<bool>,           // bit 14
    pub cansettime: Option<bool>,        // bit 15
    pub case_insensitive: Option<bool>,  // bit 16
    pub case_preserving: Option<bool>,   // bit 17
    pub fileid: Option<u64>,             // bit 20
    pub files_avail: Option<u64>,        // bit 21
    pub files_free: Option<u64>,         // bit 22
    pub files_total: Option<u64>,        // bit 23
    pub hidden: Option<bool>,            // bit 25
    pub homogeneous: Option<bool>,       // bit 26
    pub maxfilesize: Option<u64>,        // bit 27
    pub maxlink: Option<u32>,            // bit 28
    pub maxname: Option<u32>,            // bit 29
    pub maxread: Option<u64>,            // bit 30
    pub maxwrite: Option<u64>,           // bit 31
    pub mode: Option<mode4>,             // bit 33
    pub no_trunc: Option<bool>,          // bit 34
    pub numlinks: Option<u32>,           // bit 35
    pub owner: Option<nfsstring>,        // bit 36
    pub owner_group: Option<nfsstring>,  // bit 37
    pub rawdev: Option<specdata4>,       // bit 41
    pub space_avail: Option<u64>,        // bit 42
    pub space_free: Option<u64>,         // bit 43
    pub space_total: Option<u64>,        // bit 44
    pub space_used: Option<u64>,         // bit 45
    pub time_access: Option<nfstime4>,   // bit 47
    pub time_backup: Option<nfstime4>,   // bit 49
    pub time_create: Option<nfstime4>,   // bit 50
    pub time_delta: Option<nfstime4>,    // bit 51
    pub time_metadata: Option<nfstime4>, // bit 52
    pub time_modify: Option<nfstime4>,   // bit 53
    pub mounted_on_fileid: Option<u64>,  // bit 55
}

impl fattr4 {
    pub fn from_fattr3(src: &fattr3) -> fattr4 {
        Self {
            supported_attrs: Some(Vec::from(SUPPORTED_ATTRS)),
            ftype: Some(ftype4::from(src.ftype)),
            change: Some(src.ctime.seconds as changeid4),
            size: Some(src.size),
            fsid: Some(fsid4 {
                major: src.fsid,
                minor: 0,
            }),

            fileid: Some(src.fileid),
            mode: Some(src.mode),
            numlinks: Some(src.nlink),
            rawdev: Some(src.rdev),
            space_used: Some(src.used),
            time_access: Some(nfstime4 {
                seconds: src.atime.seconds as i64,
                nseconds: src.atime.nseconds,
            }),
            time_metadata: Some(nfstime4 {
                seconds: src.ctime.seconds as i64,
                nseconds: src.ctime.nseconds,
            }),
            time_modify: Some(nfstime4 {
                seconds: src.mtime.seconds as i64,
                nseconds: src.mtime.nseconds,
            }),

            ..Default::default()
        }
    }
}

const SUPPORTED_ATTRS: [u32; 2] = [
    // Word 0: bits 0..31
    (1 << 0)   // supported_attrs   (mandatory)
        | (1 << 1)   // type              (mandatory, from fattr3.ftype)
        | (1 << 2)   // fh_expire_type    (mandatory, synthesized)
        | (1 << 3)   // change            (mandatory, from fattr3.ctime)
        | (1 << 4)   // size              (mandatory, from fattr3.size)
        | (1 << 5)   // link_support      (mandatory, synthesized)
        | (1 << 6)   // symlink_support   (mandatory, synthesized)
        | (1 << 7)   // named_attr        (mandatory, synthesized)
        | (1 << 8)   // fsid              (mandatory, from fattr3.fsid)
        | (1 << 9)   // unique_handles    (mandatory, synthesized)
        | (1 << 10)  // lease_time        (mandatory, synthesized)
        | (1 << 11)  // rdattr_error      (mandatory, synthesized)
        | (1 << 19)  // filehandle        (mandatory, synthesized)
        | (1 << 20), // fileid            (recommended, from fattr3.fileid)
    // Word 1: bits 32..63
    (1 << (33 - 32))  // mode          (from fattr3.mode)
        | (1 << (35 - 32))  // numlinks      (from fattr3.nlink)
        | (1 << (36 - 32))  // owner         (from fattr3.uid via idmap)
        | (1 << (37 - 32))  // owner_group   (from fattr3.gid via idmap)
        | (1 << (41 - 32))  // rawdev        (from fattr3.rdev)
        | (1 << (45 - 32))  // space_used    (from fattr3.used)
        | (1 << (47 - 32))  // time_access   (from fattr3.atime)
        | (1 << (52 - 32))  // time_metadata (from fattr3.ctime)
        | (1 << (53 - 32)), // time_modify   (from fattr3.mtime)
];

impl XDR for fattr4 {
    fn serialize<W: Write>(&self, dest: &mut W) -> std::io::Result<()> {
        // 1. Build attrmask + encode present values into a temp buffer,
        //    both in ascending attribute (bit) order.
        let mut words = [0u32; 2]; // bits 0..63
        let mut vals: Vec<u8> = Vec::new();

        macro_rules! put {
            ($bit:expr, $field:expr) => {
                if let Some(v) = &$field {
                    words[$bit / 32] |= 1 << ($bit % 32);
                    v.serialize(&mut vals)?;
                }
            };
        }

        // Ascending bit order.
        put!(0, self.supported_attrs);
        put!(1, self.ftype);
        put!(2, self.fh_expire_type);
        put!(3, self.change);
        put!(4, self.size);
        put!(5, self.link_support);
        put!(6, self.symlink_support);
        put!(7, self.named_attr);
        put!(8, self.fsid);
        put!(9, self.unique_handles);
        put!(10, self.lease_time);
        put!(11, self.rdattr_error);
        put!(12, self.acl);
        put!(13, self.aclsupport);
        put!(14, self.archive);
        put!(15, self.cansettime);
        put!(16, self.case_insensitive);
        put!(17, self.case_preserving);
        put!(19, self.filehandle);
        put!(20, self.fileid);
        put!(21, self.files_avail);
        put!(22, self.files_free);
        put!(23, self.files_total);
        put!(25, self.hidden);
        put!(26, self.homogeneous);
        put!(27, self.maxfilesize);
        put!(28, self.maxlink);
        put!(29, self.maxname);
        put!(30, self.maxread);
        put!(31, self.maxwrite);
        put!(33, self.mode);
        put!(34, self.no_trunc);
        put!(35, self.numlinks);
        put!(36, self.owner);
        put!(37, self.owner_group);
        put!(41, self.rawdev);
        put!(42, self.space_avail);
        put!(43, self.space_free);
        put!(44, self.space_total);
        put!(45, self.space_used);
        put!(47, self.time_access);
        put!(49, self.time_backup);
        put!(50, self.time_create);
        put!(51, self.time_delta);
        put!(52, self.time_metadata);
        put!(53, self.time_modify);
        put!(55, self.mounted_on_fileid);

        // 2. Trim trailing zero words for the bitmap4.
        let mut mask = words.to_vec();
        while mask.last() == Some(&0) {
            mask.pop();
        }

        // 3. Write bitmap4: length-prefixed array of u32.
        (mask.len() as u32).serialize(dest)?;
        for w in &mask {
            w.serialize(dest)?;
        }

        // 4. Write attr_vals: opaque<> = length prefix + bytes + XDR padding.
        (vals.len() as u32).serialize(dest)?;
        dest.write_all(&vals)?;
        let pad = (4 - (vals.len() % 4)) % 4;
        if pad > 0 {
            dest.write_all(&[0u8; 4][..pad])?;
        }

        Ok(())
    }

    fn deserialize<R: Read>(&mut self, src: &mut R) -> std::io::Result<()> {
        // 1. Read bitmap4.
        let mut nwords = 0u32;
        nwords.deserialize(src)?;
        let mut mask = vec![0u32; nwords as usize];
        for w in mask.iter_mut() {
            w.deserialize(src)?;
        }

        // 2. Read attr_vals opaque: length + bytes (+ padding), decode from it.
        let mut vlen = 0u32;
        vlen.deserialize(src)?;
        let vlen = vlen as usize;
        let mut buf = vec![0u8; vlen];
        src.read_exact(&mut buf)?;
        let pad = (4 - (vlen % 4)) % 4;
        if pad > 0 {
            let mut skip = [0u8; 4];
            src.read_exact(&mut skip[..pad])?;
        }
        let mut cur = std::io::Cursor::new(buf);

        let is_set = |bit: usize| -> bool {
            let w = bit / 32;
            w < mask.len() && (mask[w] & (1 << (bit % 32))) != 0
        };

        fn read_attr<T: XDR + Default, R: Read>(src: &mut R) -> std::io::Result<T> {
            let mut v = T::default();
            v.deserialize(src)?;
            Ok(v)
        }

        // 3. Decode present values in ascending bit order.
        macro_rules! get {
            ($bit:expr, $field:expr) => {
                $field = if is_set($bit) {
                    Some(read_attr(&mut cur)?)
                } else {
                    None
                };
            };
        }

        get!(0, self.supported_attrs);
        get!(1, self.ftype);
        get!(2, self.fh_expire_type);
        get!(3, self.change);
        get!(4, self.size);
        get!(5, self.link_support);
        get!(6, self.symlink_support);
        get!(7, self.named_attr);
        get!(8, self.fsid);
        get!(9, self.unique_handles);
        get!(10, self.lease_time);
        get!(11, self.rdattr_error);
        get!(12, self.acl);
        get!(13, self.aclsupport);
        get!(14, self.archive);
        get!(15, self.cansettime);
        get!(16, self.case_insensitive);
        get!(17, self.case_preserving);
        get!(19, self.filehandle);
        get!(20, self.fileid);
        get!(21, self.files_avail);
        get!(22, self.files_free);
        get!(23, self.files_total);
        get!(25, self.hidden);
        get!(26, self.homogeneous);
        get!(27, self.maxfilesize);
        get!(28, self.maxlink);
        get!(29, self.maxname);
        get!(30, self.maxread);
        get!(31, self.maxwrite);
        get!(33, self.mode);
        get!(34, self.no_trunc);
        get!(35, self.numlinks);
        get!(36, self.owner);
        get!(37, self.owner_group);
        get!(41, self.rawdev);
        get!(42, self.space_avail);
        get!(43, self.space_free);
        get!(44, self.space_total);
        get!(45, self.space_used);
        get!(47, self.time_access);
        get!(49, self.time_backup);
        get!(50, self.time_create);
        get!(51, self.time_delta);
        get!(52, self.time_metadata);
        get!(53, self.time_modify);
        get!(55, self.mounted_on_fileid);

        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct fsid4 {
    pub major: u64,
    pub minor: u64,
}
xdr_struct!(fsid4, major, minor);

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct nfsace4 {
    pub acetype: u32,
    pub aceflag: u32,
    pub acemask: u32,
    pub who: nfsstring,
}
xdr_struct!(nfsace4, acetype, aceflag, acemask, who);

impl XDR for Vec<nfsace4> {
    fn serialize<R: Write>(&self, dest: &mut R) -> std::io::Result<()> {
        assert!(self.len() < u32::MAX as usize);
        (self.len() as u32).serialize(dest)?;
        for i in self {
            i.serialize(dest)?;
        }
        Ok(())
    }
    fn deserialize<R: Read>(&mut self, src: &mut R) -> std::io::Result<()> {
        let mut length: u32 = 0;
        length.deserialize(src)?;
        self.clear();
        for _ in 0..length {
            let mut e = nfsace4::default();
            e.deserialize(src)?;
            self.push(e);
        }
        Ok(())
    }
}

pub type specdata4 = specdata;

// ---- nfstime4: int64 seconds; uint32 nseconds ----
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct nfstime4 {
    pub seconds: i64,
    pub nseconds: u32,
}
xdr_struct!(nfstime4, seconds, nseconds);

impl From<nfstime3> for nfstime4 {
    fn from(value: nfstime3) -> Self {
        Self {
            seconds: value.seconds as i64,
            nseconds: value.nseconds,
        }
    }
}

// ---- EXCHANGE_ID (RFC 8881 §18.35) ----

pub const EXCHGID4_FLAG_SUPP_MOVED_REFER: u32 = 0x00000001;
pub const EXCHGID4_FLAG_SUPP_MOVED_MIGR: u32 = 0x00000002;
pub const EXCHGID4_FLAG_BIND_PRINC_STATEID: u32 = 0x00000100;
pub const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x00010000;
pub const EXCHGID4_FLAG_USE_PNFS_MDS: u32 = 0x00020000;
pub const EXCHGID4_FLAG_USE_PNFS_DS: u32 = 0x00040000;
pub const EXCHGID4_FLAG_MASK_PNFS: u32 = 0x00070000;
pub const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A: u32 = 0x40000000;
pub const EXCHGID4_FLAG_CONFIRMED_R: u32 = 0x80000000;

#[derive(Copy, Clone, Debug, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum state_protect_how4 {
    SP4_NONE = 0,
    SP4_MACH_CRED = 1,
    SP4_SSV = 2,
}
impl Default for state_protect_how4 {
    fn default() -> Self {
        Self::SP4_NONE
    }
}
xdr_enum_serde!(state_protect_how4);

/// client_owner4: verifier + opaque owner id
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct client_owner4 {
    pub co_verifier: verifier4,
    pub co_ownerid: Vec<u8>,
}
xdr_struct!(client_owner4, co_verifier, co_ownerid);

/// nfs_impl_id4
#[derive(Clone, Debug, Default, PartialEq)]
pub struct nfs_impl_id4 {
    pub nii_domain: utf8str_cis,
    pub nii_name: utf8str_cs,
    pub nii_date: nfstime4,
}
xdr_struct!(nfs_impl_id4, nii_domain, nii_name, nii_date);

/// Optional<nfs_impl_id4> encoded as array<0..1>
#[derive(Clone, Debug, Default, PartialEq)]
pub struct impl_id_optional(pub Option<nfs_impl_id4>);
impl XDR for impl_id_optional {
    fn serialize<W: Write>(&self, dest: &mut W) -> std::io::Result<()> {
        match &self.0 {
            None => 0u32.serialize(dest),
            Some(v) => {
                1u32.serialize(dest)?;
                v.serialize(dest)
            },
        }
    }
    fn deserialize<R: Read>(&mut self, src: &mut R) -> std::io::Result<()> {
        let mut n = 0u32;
        n.deserialize(src)?;
        if n == 0 {
            self.0 = None;
        } else {
            let mut v = nfs_impl_id4::default();
            v.deserialize(src)?;
            self.0 = Some(v);
            // skip any extra (spec allows 0..1, but be lenient)
            for _ in 1..n {
                let mut d = nfs_impl_id4::default();
                d.deserialize(src)?;
            }
        }
        Ok(())
    }
}

/// state_protect4_a — only SP4_NONE decoded fully.
/// SP4_MACH_CRED / SP4_SSV are decoded enough to stay stream-aligned.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct state_protect4_a {
    pub spa_how: state_protect_how4,
    // For SP4_MACH_CRED/SP4_SSV we hold the raw opaque tail so we stay aligned.
    pub spa_mach_ops: Option<(bitmap4, bitmap4)>, // enforce, allow (MACH_CRED)
    pub spa_ssv: Option<ssv_sp_parms4>,           // SSV
}
impl XDR for state_protect4_a {
    fn serialize<W: Write>(&self, dest: &mut W) -> std::io::Result<()> {
        self.spa_how.serialize(dest)?;
        match self.spa_how {
            state_protect_how4::SP4_NONE => {},
            state_protect_how4::SP4_MACH_CRED => {
                let (e, a) = self.spa_mach_ops.clone().unwrap_or_default();
                e.serialize(dest)?;
                a.serialize(dest)?;
            },
            state_protect_how4::SP4_SSV => {
                self.spa_ssv.clone().unwrap_or_default().serialize(dest)?;
            },
        }
        Ok(())
    }
    fn deserialize<R: Read>(&mut self, src: &mut R) -> std::io::Result<()> {
        self.spa_how.deserialize(src)?;
        match self.spa_how {
            state_protect_how4::SP4_NONE => {
                self.spa_mach_ops = None;
                self.spa_ssv = None;
            },
            state_protect_how4::SP4_MACH_CRED => {
                let mut e: bitmap4 = Vec::new();
                let mut a: bitmap4 = Vec::new();
                e.deserialize(src)?;
                a.deserialize(src)?;
                self.spa_mach_ops = Some((e, a));
            },
            state_protect_how4::SP4_SSV => {
                let mut s = ssv_sp_parms4::default();
                s.deserialize(src)?;
                self.spa_ssv = Some(s);
            },
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ssv_sp_parms4 {
    pub ssp_ops_enforce: bitmap4,
    pub ssp_ops_allow: bitmap4,
    pub ssp_hash_algs: Vec<nfsstring>,
    pub ssp_encr_algs: Vec<nfsstring>,
    pub ssp_window: u32,
    pub ssp_num_gss_handles: u32,
}
xdr_struct!(
    ssv_sp_parms4,
    ssp_ops_enforce,
    ssp_ops_allow,
    ssp_hash_algs,
    ssp_encr_algs,
    ssp_window,
    ssp_num_gss_handles
);

/// state_protect4_r — server reply. We only ever return SP4_NONE.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct state_protect4_r {
    pub spr_how: state_protect_how4,
    // SP4_NONE => nothing further.
}
xdr_struct!(state_protect4_r, spr_how);

// EXCHANGE_ID4args
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EXCHANGE_ID4args {
    pub eia_clientowner: client_owner4,
    pub eia_flags: u32,
    pub eia_state_protect: state_protect4_a,
    pub eia_client_impl_id: impl_id_optional,
}
xdr_struct!(EXCHANGE_ID4args, eia_clientowner, eia_flags, eia_state_protect, eia_client_impl_id);

// server_owner4
#[derive(Clone, Debug, Default, PartialEq)]
pub struct server_owner4 {
    pub so_minor_id: u64,
    pub so_major_id: Vec<u8>,
}
xdr_struct!(server_owner4, so_minor_id, so_major_id);

// EXCHANGE_ID4resok
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EXCHANGE_ID4resok {
    pub eir_clientid: clientid4,
    pub eir_sequenceid: sequenceid4,
    pub eir_flags: u32,
    pub eir_state_protect: state_protect4_r,
    pub eir_server_owner: server_owner4,
    pub eir_server_scope: Vec<u8>,
    pub eir_server_impl_id: impl_id_optional,
}
xdr_struct!(
    EXCHANGE_ID4resok,
    eir_clientid,
    eir_sequenceid,
    eir_flags,
    eir_state_protect,
    eir_server_owner,
    eir_server_scope,
    eir_server_impl_id
);

// ---- CREATE_SESSION (RFC 8881 §18.36) ----

pub const CREATE_SESSION4_FLAG_PERSIST: u32 = 0x00000001;
pub const CREATE_SESSION4_FLAG_CONN_BACK_CHAN: u32 = 0x00000002;
pub const CREATE_SESSION4_FLAG_CONN_RDMA: u32 = 0x00000004;

/// channel_attrs4 (RFC 8881 §18.36).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct channel_attrs4 {
    pub ca_headerpadsize: count4,
    pub ca_maxrequestsize: count4,
    pub ca_maxresponsesize: count4,
    pub ca_maxresponsesize_cached: count4,
    pub ca_maxoperations: count4,
    pub ca_maxrequests: count4,
    /// rdma_ird<0..1> — optional array of one u32.
    pub ca_rdma_ird: Vec<u32>,
}
xdr_struct!(
    channel_attrs4,
    ca_headerpadsize,
    ca_maxrequestsize,
    ca_maxresponsesize,
    ca_maxresponsesize_cached,
    ca_maxoperations,
    ca_maxrequests,
    ca_rdma_ird
);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct callback_sec_parms4 {
    pub cb_secflavor: u32,
    /// AUTH_SYS body (authsys_parms) or raw GSS body, kept for alignment.
    pub cb_sys: Option<cbsp_authsys>,
    pub cb_gss_raw: Option<Vec<u8>>, // not parsed; we reject GSS anyway
}
impl XDR for callback_sec_parms4 {
    fn serialize<W: Write>(&self, dest: &mut W) -> std::io::Result<()> {
        self.cb_secflavor.serialize(dest)?;
        match self.cb_secflavor {
            0 => {}, // AUTH_NONE: void
            1 => {
                self.cb_sys.clone().unwrap_or_default().serialize(dest)?;
            },
            _ => {
                // We never emit GSS; nothing to write for our purposes.
            },
        }
        Ok(())
    }
    fn deserialize<R: Read>(&mut self, src: &mut R) -> std::io::Result<()> {
        self.cb_secflavor.deserialize(src)?;
        match self.cb_secflavor {
            0 => {
                self.cb_sys = None;
                self.cb_gss_raw = None;
            },
            1 => {
                let mut s = cbsp_authsys::default();
                s.deserialize(src)?;
                self.cb_sys = Some(s);
            },
            6 => {
                // RPCSEC_GSS callback params: gcbp_service (u32) +
                // gcbp_handle_from_server<> + gcbp_handle_from_client<>.
                let mut _service = 0u32;
                _service.deserialize(src)?;
                let mut h1: Vec<u8> = Vec::new();
                let mut h2: Vec<u8> = Vec::new();
                h1.deserialize(src)?;
                h2.deserialize(src)?;
                self.cb_gss_raw = Some(Vec::new());
            },
            _ => {
                // Unknown flavor: we cannot know its body length. Abort.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported callback_sec_parms flavor",
                ));
            },
        }
        Ok(())
    }
}

impl XDR for Vec<callback_sec_parms4> {
    fn serialize<R: Write>(&self, dest: &mut R) -> std::io::Result<()> {
        (self.len() as u32).serialize(dest)?;
        for e in self {
            e.serialize(dest)?;
        }
        Ok(())
    }

    fn deserialize<R: Read>(&mut self, src: &mut R) -> std::io::Result<()> {
        let mut n = 0u32;
        n.deserialize(src)?;
        self.clear();
        for _ in 0..n {
            let mut e = callback_sec_parms4::default();
            e.deserialize(src)?;
            self.push(e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct cbsp_authsys {
    pub stamp: u32,
    pub machinename: nfsstring,
    pub uid: u32,
    pub gid: u32,
    pub gids: Vec<u32>,
}
xdr_struct!(cbsp_authsys, stamp, machinename, uid, gid, gids);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CREATE_SESSION4args {
    pub csa_clientid: clientid4,
    pub csa_sequence: sequenceid4,
    pub csa_flags: u32,
    pub csa_fore_chan_attrs: channel_attrs4,
    pub csa_back_chan_attrs: channel_attrs4,
    pub csa_cb_program: u32,
    pub csa_sec_parms: Vec<callback_sec_parms4>,
}
xdr_struct!(
    CREATE_SESSION4args,
    csa_clientid,
    csa_sequence,
    csa_flags,
    csa_fore_chan_attrs,
    csa_back_chan_attrs,
    csa_cb_program,
    csa_sec_parms
);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CREATE_SESSION4resok {
    pub csr_sessionid: sessionid4,
    pub csr_sequence: sequenceid4,
    pub csr_flags: u32,
    pub csr_fore_chan_attrs: channel_attrs4,
    pub csr_back_chan_attrs: channel_attrs4,
}
xdr_struct!(
    CREATE_SESSION4resok,
    csr_sessionid,
    csr_sequence,
    csr_flags,
    csr_fore_chan_attrs,
    csr_back_chan_attrs
);

// ---- DESTROY_SESSION (RFC 8881 §18.37) ----

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DESTROY_SESSION4args {
    pub dsa_sessionid: sessionid4,
}
xdr_struct!(DESTROY_SESSION4args, dsa_sessionid);

// ---- DESTROY_CLIENTID (RFC 8881 §18.50) ----

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DESTROY_CLIENTID4args {
    pub dca_clientid: clientid4,
}
xdr_struct!(DESTROY_CLIENTID4args, dca_clientid);

// ---- SEQUENCE (RFC 8881 §18.46) ----

pub const SEQ4_STATUS_CB_PATH_DOWN: u32 = 0x00000001;
pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING: u32 = 0x00000002;
pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED: u32 = 0x00000004;
pub const SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED: u32 = 0x00000008;
pub const SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED: u32 = 0x00000010;
pub const SEQ4_STATUS_ADMIN_STATE_REVOKED: u32 = 0x00000020;
pub const SEQ4_STATUS_RECALLABLE_STATE_REVOKED: u32 = 0x00000040;
pub const SEQ4_STATUS_LEASE_MOVED: u32 = 0x00000080;
pub const SEQ4_STATUS_RESTART_RECLAIM_NEEDED: u32 = 0x00000100;
pub const SEQ4_STATUS_CB_PATH_DOWN_SESSION: u32 = 0x00000200;
pub const SEQ4_STATUS_BACKCHANNEL_FAULT: u32 = 0x00000400;
pub const SEQ4_STATUS_DEVID_CHANGED: u32 = 0x00000800;
pub const SEQ4_STATUS_DEVID_DELETED: u32 = 0x00001000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SEQUENCE4args {
    pub sa_sessionid: sessionid4,
    pub sa_sequenceid: sequenceid4,
    pub sa_slotid: slotid4,
    pub sa_highest_slotid: slotid4,
    pub sa_cachethis: bool,
}
xdr_struct!(SEQUENCE4args, sa_sessionid, sa_sequenceid, sa_slotid, sa_highest_slotid, sa_cachethis);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SEQUENCE4resok {
    pub sr_sessionid: sessionid4,
    pub sr_sequenceid: sequenceid4,
    pub sr_slotid: slotid4,
    pub sr_highest_slotid: slotid4,
    pub sr_target_highest_slotid: slotid4,
    pub sr_status_flags: u32,
}
xdr_struct!(
    SEQUENCE4resok,
    sr_sessionid,
    sr_sequenceid,
    sr_slotid,
    sr_highest_slotid,
    sr_target_highest_slotid,
    sr_status_flags
);
