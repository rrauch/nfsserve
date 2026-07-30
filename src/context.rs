use std::fmt;
use std::sync::{Arc, Mutex};

use crate::nfs4::{clientid4, NFS4State};
use crate::transaction_tracker::TransactionTracker;
use crate::vfs::NFSFileSystem;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct RPCContext {
    pub local_port: u16,
    pub client_addr: String,
    pub auth: crate::rpc::auth_unix,
    pub vfs: Arc<dyn NFSFileSystem + Send + Sync>,
    pub mount_signal: Option<mpsc::Sender<bool>>,
    pub export_name: Arc<String>,
    pub transaction_tracker: Arc<TransactionTracker>,
    pub epoch: u32,
    pub(crate) nfs4_state: Arc<NFS4State>,
    pub(super) client_id: Arc<Mutex<Option<clientid4>>>,
}

impl RPCContext {
    pub(crate) fn set_client_id(&self, client_id: clientid4) {
        let mut guard = self.client_id.lock().unwrap();
        *guard = Some(client_id);
    }

    pub(crate) fn clear_client_id(&self) {
        let mut guard = self.client_id.lock().unwrap();
        *guard = None;
    }

    pub(crate) fn client_id(&self) -> Option<clientid4> {
        *self.client_id.lock().unwrap()
    }
}

impl fmt::Debug for RPCContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RPCContext")
            .field("local_port", &self.local_port)
            .field("client_addr", &self.client_addr)
            .field("auth", &self.auth)
            .finish()
    }
}
