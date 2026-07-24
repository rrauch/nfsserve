use async_trait::async_trait;

use crate::nfs3;
use crate::nfs3::*;
#[derive(Default, Debug)]
pub struct DirEntrySimple {
    pub fileid: fileid3,
    pub name: filename3,
}
#[derive(Default, Debug)]
pub struct ReadDirSimpleResult {
    pub entries: Vec<DirEntrySimple>,
    pub end: bool,
}

#[derive(Default, Debug)]
pub struct DirEntry {
    pub fileid: fileid3,
    pub name: filename3,
    pub attr: fattr3,
}
#[derive(Default, Debug)]
pub struct ReadDirResult {
    pub entries: Vec<DirEntry>,
    pub end: bool,
}

impl ReadDirSimpleResult {
    fn from_readdir_result(result: &ReadDirResult) -> ReadDirSimpleResult {
        let entries: Vec<DirEntrySimple> = result
            .entries
            .iter()
            .map(|e| DirEntrySimple {
                fileid: e.fileid,
                name: e.name.clone(),
            })
            .collect();
        ReadDirSimpleResult {
            entries,
            end: result.end,
        }
    }
}

/// What capabilities are supported
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum VFSCapabilities {
    ReadOnly,
    ReadWrite,
}

/// The mode in which a file is opened
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
}

#[allow(non_camel_case_types)]
/// Represents a reference to an open file handle
pub type vfs_fh = u32;

/// The basic API to implement to provide an NFS file system
///
/// Opaque FH
/// ---------
/// Files are only uniquely identified by a 64-bit file id. (basically an inode number)
/// We automatically produce internally the opaque filehandle which is comprised of
///  - A 64-bit generation number derived from the server startup time
///   (i.e. so the opaque file handle expires when the NFS server restarts)
///  - The 64-bit file id
//
/// readdir pagination
/// ------------------
/// We do not use cookie verifier. We just use the start_after.  The
/// implementation should allow startat to start at any position. That is,
/// the next query to readdir may be the last entry in the previous readdir
/// response.
//
/// There is a wierd annoying thing about readdir that limits the number
/// of bytes in the response (instead of the number of entries). The caller
/// will have to truncate the readdir response / issue more calls to readdir
/// accordingly to fill up the expected number of bytes without exceeding it.
//
/// Other requirements
/// ------------------
///  getattr needs to be fast. NFS uses that a lot
//
///  The 0 fileid is reserved and should not be used
#[async_trait]
pub trait NFSFileSystem: Sync {
    /// Returns the set of capabilities supported
    fn capabilities(&self) -> VFSCapabilities;
    /// Returns the ID the of the root directory "/"
    fn root_dir(&self) -> fileid3;
    /// Look up the id of a path in a directory
    ///
    /// i.e. given a directory dir/ containing a file a.txt
    /// this may call lookup(id_of("dir/"), "a.txt")
    /// and this should return the id of the file "dir/a.txt"
    ///
    /// This method should be fast as it is used very frequently.
    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3>;

    /// Returns the attributes of an id.
    /// This method should be fast as it is used very frequently.
    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3>;

    /// Sets the attributes of an id
    /// this should return Err(nfsstat3::NFS3ERR_ROFS) if readonly
    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3>;

    /// Opens a file for reading or writing, returning a file handle.
    /// Returns Err(nfsstat3::NFS3ERR_ISDIR) if the id refers to a directory.
    /// If opened for writing on a readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS). Optional.
    async fn open(&self, id: fileid3, mode: OpenMode) -> Result<vfs_fh, nfsstat3> {
        let attr = self.getattr(id).await?;
        if attr.ftype == ftype3::NF3DIR {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        if mode == OpenMode::ReadWrite && (self.capabilities() == VFSCapabilities::ReadOnly) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        // generate a random fh
        Ok(getrandom::u32().expect("OS RNG failure"))
    }

    /// Closes a previously opened file handle.
    #[allow(unused)]
    async fn close(&self, fh: vfs_fh) -> Result<(), nfsstat3> {
        Ok(())
    }

    /// Reads the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, all bytes till the end of file are returned.
    /// EOF must be flagged if the end of the file is reached by the read.
    async fn read(&self, fh: vfs_fh, id: fileid3, offset: u64, count: u32) -> Result<(Vec<u8>, bool), nfsstat3>;

    /// Writes the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, the file is extended.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn write(&self, fh: vfs_fh, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3>;

    /// Creates a file with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create(&self, dirid: fileid3, filename: &filename3, attr: sattr3) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Creates a file if it does not already exist
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create_exclusive(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3>;

    /// Makes a directory with the following attributes.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn mkdir(&self, dirid: fileid3, dirname: &filename3) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3>;

    /// Renames a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3>;

    /// Returns the contents of a directory with pagination.
    /// Directory listing should be deterministic.
    /// Up to max_entries may be returned, and start_after is used
    /// to determine where to start returning entries from.
    ///
    /// For instance if the directory has entry with ids [1,6,2,11,8,9]
    /// and start_after=6, readdir should returning 2,11,8,...
    //
    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3>;

    /// Simple version of readdir.
    /// Only need to return filename and id
    async fn readdir_simple(&self, dirid: fileid3, count: usize) -> Result<ReadDirSimpleResult, nfsstat3> {
        Ok(ReadDirSimpleResult::from_readdir_result(&self.readdir(dirid, 0, count).await?))
    }

    /// Makes a symlink with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Reads a symlink
    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3>;

    /// Get static file system Information
    async fn fsinfo(&self, root_fileid: fileid3) -> Result<fsinfo3, nfsstat3> {
        let dir_attr: nfs3::post_op_attr = match self.getattr(root_fileid).await {
            Ok(v) => nfs3::post_op_attr::attributes(v),
            Err(_) => nfs3::post_op_attr::Void,
        };

        let res = fsinfo3 {
            obj_attributes: dir_attr,
            rtmax: 1024 * 1024,
            rtpref: 1024 * 124,
            rtmult: 1024 * 1024,
            wtmax: 1024 * 1024,
            wtpref: 1024 * 1024,
            wtmult: 1024 * 1024,
            dtpref: 1024 * 1024,
            maxfilesize: 128 * 1024 * 1024 * 1024,
            time_delta: nfs3::nfstime3 {
                seconds: 0,
                nseconds: 1000000,
            },
            properties: nfs3::FSF_SYMLINK | nfs3::FSF_HOMOGENEOUS | nfs3::FSF_CANSETTIME,
        };
        Ok(res)
    }

    /// Converts a complete path to a fileid.  Optional.
    /// The default implementation walks the directory structure with lookup()
    async fn path_to_id(&self, path: &[u8]) -> Result<fileid3, nfsstat3> {
        let splits = path.split(|&r| r == b'/');
        let mut fid = self.root_dir();
        for component in splits {
            if component.is_empty() {
                continue;
            }
            fid = self.lookup(fid, &component.into()).await?;
        }
        Ok(fid)
    }
}
