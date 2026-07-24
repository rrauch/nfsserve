use crate::xdr::*;
use crate::xdr_struct;

use crate::nfs3::{fileid3, nfs_fh3, nfsstat3};
use crate::nfs4::NFS4State;
use std::fmt;
use std::io::{Read, Write};

pub const PROGRAM: u32 = 100003;

#[allow(non_camel_case_types)]
#[derive(Default, Clone, PartialEq, Eq)]
pub struct nfsstring(pub Vec<u8>);
impl nfsstring {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

xdr_vec!(nfsstring);

impl From<Vec<u8>> for nfsstring {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}
impl From<String> for nfsstring {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}
impl From<&[u8]> for nfsstring {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}
impl AsRef<[u8]> for nfsstring {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for nfsstring {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl fmt::Debug for nfsstring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}
impl fmt::Display for nfsstring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}

#[allow(non_camel_case_types)]
pub type opaque = u8;

/// File Handle information
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq)]
pub struct nfs_fh {
    pub data: Vec<u8>,
}
xdr_struct!(nfs_fh, data);
#[allow(clippy::derivable_impls)]
impl Default for nfs_fh {
    fn default() -> Self {
        Self { data: Vec::new() }
    }
}

/// Device Number information. Ex: Major / Minor device
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct specdata {
    pub specdata1: u32,
    pub specdata2: u32,
}
xdr_struct!(specdata, specdata1, specdata2);

/// Converts the fileid to an opaque NFS file handle..
pub(crate) fn id_to_fh(state: &NFS4State, id: fileid3) -> nfs_fh3 {
    let gennum = state.boot_verifier();
    let mut ret: Vec<u8> = Vec::new();
    ret.extend_from_slice(&gennum.to_le_bytes());
    ret.extend_from_slice(&gennum.to_le_bytes()); // padding
    ret.extend_from_slice(&id.to_le_bytes());
    nfs_fh3 { data: ret }
}
/// Converts an opaque NFS file handle to a fileid..
pub(crate) fn fh_to_id(state: &NFS4State, id: &nfs_fh3) -> Result<fileid3, nfsstat3> {
    if id.data.len() != 16 {
        return Err(nfsstat3::NFS3ERR_BADHANDLE);
    }
    let gen = u32::from_le_bytes(id.data[0..4].try_into().unwrap());
    let padding = u32::from_le_bytes(id.data[4..8].try_into().unwrap());
    let id = u64::from_le_bytes(id.data[8..16].try_into().unwrap());

    if gen != padding {
        return Err(nfsstat3::NFS3ERR_BADHANDLE);
    }
    if gen != state.boot_verifier() {
        return Err(nfsstat3::NFS3ERR_STALE);
    }
    Ok(id)
}
