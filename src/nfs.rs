use crate::xdr::*;
use crate::xdr_struct;

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
impl From<Vec<u8>> for nfsstring {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
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
