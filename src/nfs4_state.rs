#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::nfs4::{channel_attrs4, clientid4, sequenceid4, sessionid4, slotid4, stateid4, verifier4, NFS4_OTHER_SIZE};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

pub struct NFS4State {
    inner: Arc<Mutex<Inner>>,
    _reaper: JoinHandle<()>,
}

impl Drop for NFS4State {
    fn drop(&mut self) {
        self._reaper.abort();
    }
}

struct OpenState {
    clientid: clientid4,
    owner: Vec<u8>,
    fileid: u64,
    /// Current stateid seqid; bumped on every state-mutating op (e.g. CLOSE
    /// would consume/close it). Starts at 1.
    seqid: u32,
    share_access: u32,
    share_deny: u32,
}

#[derive(Default)]
struct OpenOwnerState {
    /// Last open_owner seqid seen (OPEN/CLOSE ordering, 4.0-style).
    /// In 4.1 sequencing is via SEQUENCE, but the field is still carried.
    last_seqid: u32,
}

struct Inner {
    lease: Duration,
    /// Per-boot verifier, occupies the high 32 bits of every clientid so that
    /// clientids issued before a server restart reliably become STALE.
    boot_verifier: u32,
    /// co_ownerid bytes -> client record
    clients: HashMap<Vec<u8>, ClientRecord>,
    /// clientid -> co_ownerid (reverse index)
    clientid_index: HashMap<clientid4, Vec<u8>>,
    /// sessionid -> session record
    sessions: HashMap<sessionid4, SessionRecord>,
    /// stateid.other -> open state record.
    opens: HashMap<[u8; NFS4_OTHER_SIZE], OpenState>,
    /// (clientid, open_owner bytes) -> per-owner seqid bookkeeping.
    open_owners: HashMap<(clientid4, Vec<u8>), OpenOwnerState>,
}

impl Inner {
    /// Generate a collision-free clientid: high 32 bits = boot verifier,
    /// low 32 bits = CSPRNG value.
    fn fresh_clientid(&self) -> clientid4 {
        loop {
            let low = getrandom::u32().expect("OS RNG failure") as u64;
            let cid = ((self.boot_verifier as u64) << 32) | low;
            if !self.clientid_index.contains_key(&cid) {
                break cid;
            }
        }
    }

    /// Generate a collision-free 16-byte sessionid.
    fn fresh_sessionid(&self) -> sessionid4 {
        loop {
            let mut sid = [0u8; 16];
            getrandom::fill(&mut sid).expect("OS RNG failure");
            if !self.sessions.contains_key(&sid) {
                break sid;
            }
        }
    }

    /// Generate a collision-free 12-byte stateid.other.
    fn fresh_stateid_other(&self) -> [u8; NFS4_OTHER_SIZE] {
        loop {
            let mut other = [0u8; NFS4_OTHER_SIZE];
            getrandom::fill(&mut other).expect("OS RNG failure");
            if !self.opens.contains_key(&other) {
                break other;
            }
        }
    }

    /// Remove a client, its reverse index, and all its sessions and open file handles.
    fn expire_client(&mut self, ownerid: &[u8]) {
        if let Some(rec) = self.clients.remove(ownerid) {
            self.clientid_index.remove(&rec.clientid);
            let cid = rec.clientid;
            self.sessions.retain(|_, sess| sess.clientid != cid);
            self.opens.retain(|_, o| o.clientid != cid);
            self.open_owners.retain(|(c, _), _| *c != cid);
        }
    }

    /// Purge all clients whose lease has expired.
    fn sweep_expired(&mut self) {
        let now = Instant::now();
        let dead: Vec<Vec<u8>> = self
            .clients
            .iter()
            .filter(|(_, r)| r.expires < now)
            .map(|(k, _)| k.clone())
            .collect();
        for owner in dead {
            self.expire_client(&owner);
        }
    }
}

struct ClientRecord {
    clientid: clientid4,
    co_verifier: verifier4,
    /// Next expected CREATE_SESSION sequenceid.
    seqid: sequenceid4,
    confirmed: bool,
    sessions: Vec<sessionid4>,
    expires: Instant,
    reclaim_complete: bool,
}

struct SessionRecord {
    clientid: clientid4,
    slots: Vec<SlotState>,
    fore_attrs: channel_attrs4,
    back_attrs: channel_attrs4,
}

#[derive(Clone, Default)]
struct SlotState {
    /// Last sequenceid seen. 0 => slot never used.
    last_seqid: sequenceid4,
    /// Full cached COMPOUND4res body (status+tag+resarray), if sa_cachethis.
    cached_reply: Option<Vec<u8>>,
}

// ---- EXCHANGE_ID outcome ----
pub struct ExchangeIdResult {
    pub clientid: clientid4,
    pub seqid: sequenceid4,
}

// ---- CREATE_SESSION outcome ----
pub enum CreateSessionOutcome {
    Ok {
        sessionid: sessionid4,
    },
    StaleClientId,
    SeqMisordered,
    /// Replay of the CREATE_SESSION that created this session.
    Replay {
        sessionid: sessionid4,
    },
}

// ---- SEQUENCE outcome ----
pub enum SequenceOutcome {
    New,
    Replay(Vec<u8>),
    RetryUncached,
    Misordered,
    BadSession,
    BadSlot,
}

impl NFS4State {
    pub fn new(lease: Duration) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            lease,
            boot_verifier: getrandom::u32().expect("OS RNG failure"),
            clients: HashMap::new(),
            clientid_index: HashMap::new(),
            sessions: HashMap::new(),
            opens: HashMap::new(),
            open_owners: HashMap::new(),
        }));

        let _reaper = {
            let inner = inner.clone();
            tokio::task::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    {
                        let mut g = inner.lock().unwrap();
                        g.sweep_expired();
                    }
                }
            })
        };

        Self { inner, _reaper }
    }

    /// EXCHANGE_ID: create or refresh an (unconfirmed) client record.
    /// If the same ownerid returns with a new verifier, the client rebooted;
    /// we replace the record (and orphan its old sessions — a real impl would
    /// expire them; single-slot skeleton drops references lazily).
    pub fn exchange_id(&self, co_ownerid: &[u8], co_verifier: &verifier4) -> ExchangeIdResult {
        let mut g = self.inner.lock().unwrap();

        if let Some(rec) = g.clients.get(co_ownerid) {
            if &rec.co_verifier == co_verifier {
                // Same client, same boot: return existing.
                return ExchangeIdResult {
                    clientid: rec.clientid,
                    seqid: rec.seqid,
                };
            }
            // Verifier changed => client rebooted. Drop old record + sessions.
            let old_cid = rec.clientid;
            let old_sessions = rec.sessions.clone();
            g.clientid_index.remove(&old_cid);
            for sid in old_sessions {
                g.sessions.remove(&sid);
            }
            g.clients.remove(co_ownerid);
        }

        let clientid = g.fresh_clientid();
        let lease = g.lease;

        g.clients.insert(
            co_ownerid.to_vec(),
            ClientRecord {
                clientid,
                co_verifier: *co_verifier,
                seqid: 1, // starting CREATE_SESSION seqid
                confirmed: false,
                sessions: Vec::new(),
                expires: Instant::now() + lease,
                reclaim_complete: false,
            },
        );
        g.clientid_index.insert(clientid, co_ownerid.to_vec());

        ExchangeIdResult { clientid, seqid: 1 }
    }

    /// CREATE_SESSION: validate clientid + seqid, allocate a session.
    /// `num_slots` = negotiated ca_maxrequests (>=1).
    pub fn create_session(
        &self,
        clientid: clientid4,
        csa_sequence: sequenceid4,
        num_slots: u32,
        fore_attrs: channel_attrs4,
        back_attrs: channel_attrs4,
    ) -> CreateSessionOutcome {
        let mut g = self.inner.lock().unwrap();

        let ownerid = match g.clientid_index.get(&clientid) {
            Some(o) => o.clone(),
            None => return CreateSessionOutcome::StaleClientId,
        };

        // Read current expected seqid.
        let expected = g.clients.get(&ownerid).unwrap().seqid;

        // RFC 8881 §18.36.4: csa_sequence must equal the clientid's seqid.
        // Replay: csa_sequence == expected-1 and a session already exists.
        if csa_sequence == expected {
            // New CREATE_SESSION: allocate.
            let sessionid = g.fresh_sessionid();

            let slots = vec![SlotState::default(); num_slots.max(1) as usize];
            g.sessions.insert(
                sessionid,
                SessionRecord {
                    clientid,
                    slots,
                    fore_attrs,
                    back_attrs,
                },
            );

            let rec = g.clients.get_mut(&ownerid).unwrap();
            rec.confirmed = true; // CREATE_SESSION confirms client
            rec.seqid = expected.wrapping_add(1);
            rec.sessions.push(sessionid);

            CreateSessionOutcome::Ok { sessionid }
        } else if csa_sequence == expected.wrapping_sub(1) {
            // Replay of the last CREATE_SESSION. Return its sessionid.
            let rec = g.clients.get(&ownerid).unwrap();
            match rec.sessions.last() {
                Some(&sessionid) => CreateSessionOutcome::Replay { sessionid },
                None => CreateSessionOutcome::SeqMisordered,
            }
        } else {
            CreateSessionOutcome::SeqMisordered
        }
    }

    /// SEQUENCE slot check. Advances slot on New.
    /// Renews lease if valid.
    pub fn sequence_check(&self, sessionid: &sessionid4, slotid: slotid4, seqid: sequenceid4) -> SequenceOutcome {
        let mut g = self.inner.lock().unwrap();

        // Resolve owning client.
        let clientid = match g.sessions.get(sessionid) {
            Some(s) => s.clientid,
            None => return SequenceOutcome::BadSession,
        };
        let ownerid = match g.clientid_index.get(&clientid) {
            Some(o) => o.clone(),
            None => return SequenceOutcome::BadSession,
        };

        // Lease check: expired => purge whole client, session is now gone.
        let lease = g.lease;
        let now = Instant::now();
        let expired = g.clients.get(&ownerid).map(|r| r.expires < now).unwrap_or(true);
        if expired {
            g.expire_client(&ownerid);
            return SequenceOutcome::BadSession;
        }

        // Slot processing.
        let sess = g.sessions.get_mut(sessionid).unwrap();
        let slot = match sess.slots.get_mut(slotid as usize) {
            Some(s) => s,
            None => return SequenceOutcome::BadSlot,
        };

        let outcome = if seqid == slot.last_seqid {
            match &slot.cached_reply {
                Some(bytes) => SequenceOutcome::Replay(bytes.clone()),
                None => SequenceOutcome::RetryUncached,
            }
        } else if seqid == slot.last_seqid.wrapping_add(1) {
            slot.last_seqid = seqid;
            slot.cached_reply = None;
            SequenceOutcome::New
        } else {
            SequenceOutcome::Misordered
        };

        // Any valid SEQUENCE renews the client lease (not Misordered/BadSlot).
        if !matches!(outcome, SequenceOutcome::Misordered | SequenceOutcome::BadSlot) {
            if let Some(rec) = g.clients.get_mut(&ownerid) {
                rec.expires = now + lease;
            }
        }

        outcome
    }

    /// Store the full COMPOUND4res reply for a slot (sa_cachethis case).
    pub fn cache_reply(&self, sessionid: &sessionid4, slotid: slotid4, seqid: sequenceid4, reply: Vec<u8>) {
        let mut g = self.inner.lock().unwrap();
        if let Some(sess) = g.sessions.get_mut(sessionid) {
            if let Some(slot) = sess.slots.get_mut(slotid as usize) {
                if slot.last_seqid == seqid {
                    slot.cached_reply = Some(reply);
                }
            }
        }
    }

    /// DESTROY_SESSION: remove session + unlink from client.
    pub fn destroy_session(&self, sessionid: &sessionid4) -> bool {
        let mut g = self.inner.lock().unwrap();
        match g.sessions.remove(sessionid) {
            Some(sess) => {
                if let Some(owner) = g.clientid_index.get(&sess.clientid).cloned() {
                    if let Some(rec) = g.clients.get_mut(&owner) {
                        rec.sessions.retain(|s| s != sessionid);
                    }
                }
                true
            },
            None => false,
        }
    }

    /// DESTROY_CLIENTID: reject if sessions still exist (CLIENTID_BUSY).
    pub fn destroy_clientid(&self, clientid: clientid4) -> DestroyClientIdOutcome {
        let mut g = self.inner.lock().unwrap();
        let owner = match g.clientid_index.get(&clientid).cloned() {
            Some(o) => o,
            None => return DestroyClientIdOutcome::StaleClientId,
        };
        let has_sessions = g.clients.get(&owner).map(|r| !r.sessions.is_empty()).unwrap_or(false);
        if has_sessions {
            return DestroyClientIdOutcome::Busy;
        }
        g.expire_client(&owner);
        DestroyClientIdOutcome::Ok
    }

    /// Mark the client owning `sessionid` as having completed reclaim.
    /// Idempotent; no-op if the session/client is gone.
    pub fn set_reclaim_complete(&self, sessionid: &sessionid4) {
        let mut g = self.inner.lock().unwrap();
        let clientid = match g.sessions.get(sessionid) {
            Some(s) => s.clientid,
            None => return,
        };
        if let Some(ownerid) = g.clientid_index.get(&clientid).cloned() {
            if let Some(rec) = g.clients.get_mut(&ownerid) {
                rec.reclaim_complete = true;
            }
        }
    }

    /// Record a new open. Always grants (no conflict checking).
    /// Returns a freshly minted stateid.
    pub fn open(
        &self,
        clientid: clientid4,
        owner: &[u8],
        owner_seqid: u32,
        fileid: u64,
        share_access: u32,
        share_deny: u32,
    ) -> OpenOutcome {
        let mut g = self.inner.lock().unwrap();

        // Client must exist/be confirmed.
        if !g.clientid_index.contains_key(&clientid) {
            return OpenOutcome::StaleClientId;
        }

        // Track the open_owner seqid (recorded, not strictly enforced in 4.1).
        g.open_owners.entry((clientid, owner.to_vec())).or_default().last_seqid = owner_seqid;

        let other = g.fresh_stateid_other();
        g.opens.insert(
            other,
            OpenState {
                clientid,
                owner: owner.to_vec(),
                fileid,
                seqid: 1,
                share_access,
                share_deny,
            },
        );

        OpenOutcome::Ok {
            stateid: stateid4 { seqid: 1, other },
        }
    }

    /// Validate a stateid for READ/WRITE. Returns the fileid on success.
    /// Accepts special stateids (all-zero / all-one) as anonymous access.
    pub fn resolve_stateid(&self, sid: &stateid4) -> ResolveStateid {
        // Special stateids: seqid 0 or 0xffffffff with all-zero/all-one other.
        let all_zero = sid.other == [0u8; NFS4_OTHER_SIZE];
        let all_one = sid.other == [0xffu8; NFS4_OTHER_SIZE];
        if all_zero || all_one {
            return ResolveStateid::Special;
        }

        let g = self.inner.lock().unwrap();
        match g.opens.get(&sid.other) {
            Some(o) => ResolveStateid::Open {
                fileid: o.fileid,
                share_access: o.share_access,
            },
            None => ResolveStateid::Bad,
        }
    }

    /// CLOSE: remove the open state. Returns the bumped stateid on success.
    pub fn close(&self, sid: &stateid4) -> CloseOutcome {
        let mut g = self.inner.lock().unwrap();
        match g.opens.remove(&sid.other) {
            Some(mut o) => {
                o.seqid = o.seqid.wrapping_add(1);
                CloseOutcome::Ok {
                    stateid: stateid4 {
                        seqid: o.seqid,
                        other: sid.other,
                    },
                }
            },
            None => CloseOutcome::Bad,
        }
    }

    /// Stable per-boot write verifier (8 bytes). Derived from boot_verifier.
    pub fn write_verifier(&self) -> [u8; 8] {
        let g = self.inner.lock().unwrap();
        let mut v = [0u8; 8];
        v[0..4].copy_from_slice(&g.boot_verifier.to_le_bytes());
        // low half constant; only the boot half must change across restarts.
        v[4..8].copy_from_slice(&0xA5A5_A5A5u32.to_le_bytes());
        v
    }
}

pub enum DestroyClientIdOutcome {
    Ok,
    StaleClientId,
    Busy,
}

pub enum OpenOutcome {
    Ok { stateid: stateid4 },
    StaleClientId,
}

pub enum ResolveStateid {
    Open { fileid: u64, share_access: u32 },
    Special,
    Bad,
}

pub enum CloseOutcome {
    Ok { stateid: stateid4 },
    Bad,
}
