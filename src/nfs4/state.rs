//! NFSv4.0 / 4.1 server state: clients, sessions, and open file state.

use crate::nfs4::{
    clientid4, fileid4, nfsstat4, seqid4, sequenceid4, sessionid4, slotid4, stateid4, verifier4, NFS4_OTHER_SIZE,
};
use crate::vfs::{vfs_fh, NFSFileSystem, OpenMode};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// `stateid4.other`.
type Other = [u8; NFS4_OTHER_SIZE];
/// Every fallible operation fails with an NFS status; nothing else.
type Res<T> = Result<T, nfsstat4>;
/// The reply an open-owner's last request produced. An error is as much a reply
/// as a stateid, and must be replayed just as faithfully (RFC 7530 §9.1.7).
type OwnerReply = Res<stateid4>;

/// Upper bound on slots per session, whatever the client asks for.
const MAX_SLOTS: u32 = 1;
/// Sweep interval for lapsed leases.
const REAP_INTERVAL: Duration = Duration::from_secs(30);

/// Minor version. Owner ids from SETCLIENTID and EXCHANGE_ID are unrelated
/// opaque blobs, so they must not share a namespace.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Minor {
    V40,
    V41,
}

/// The open-owner seqid an OPEN / OPEN_CONFIRM / CLOSE arrived with.
///
/// OPEN and CLOSE carry a seqid field in *both* minor versions, but RFC 8881
/// §18.16.1 / §18.2.1 require a 4.1 server to ignore it: SEQUENCE already
/// provides exactly-once semantics, and 4.1 clients are under no obligation to
/// advance it. Callers must therefore construct this from the *negotiated
/// minor version*, never from the field merely being present on the wire.
///
/// This used to be an `Option<seqid4>`, which conflated "which minor version"
/// with "the seqid value". A dispatcher that forwarded `Some(args.seqid)` for a
/// 4.1 client made every CLOSE look like a replay of the preceding OPEN, so
/// `close` returned NFS4_OK early and never released the open state — leaking
/// the VFS handle for the lifetime of the mount. `Inner::owner_seqid_for` now
/// re-derives the answer from the client record so no call site can reintroduce
/// that.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum OwnerSeqid {
    /// NFSv4.0: the seqid governs replay detection for this open-owner.
    V40(seqid4),
    /// NFSv4.1: no open-owner sequencing; the wire field is ignored.
    V41,
}

/// Does `status` leave the client's open-owner seqid *un*advanced?
///
/// RFC 7530 §9.1.7: the seqid advances on every request that names the
/// open-owner, successful or not, except for this exact list. Recording only
/// successes drifts the server's mirror behind the client by one per failed
/// request, and the next legitimate request then looks like a gap and draws
/// NFS4ERR_BAD_SEQID — permanently, since nothing ever resynchronises.
fn seqid_retained(status: &nfsstat4) -> bool {
    matches!(
        status,
        nfsstat4::NFS4ERR_STALE_CLIENTID
            | nfsstat4::NFS4ERR_STALE_STATEID
            | nfsstat4::NFS4ERR_BAD_STATEID
            | nfsstat4::NFS4ERR_BAD_SEQID
            | nfsstat4::NFS4ERR_BADXDR
            | nfsstat4::NFS4ERR_RESOURCE
            | nfsstat4::NFS4ERR_NOFILEHANDLE
            | nfsstat4::NFS4ERR_MOVED
    )
}

// ---------------------------------------------------------------- file handles

/// A `vfs_fh` that is closed via the background closer once the last clone is
/// dropped. Refcounted so that in-flight READs survive a mode upgrade
/// replacing the handle, or a concurrent CLOSE.
#[derive(Clone, Debug)]
pub struct ManagedFileHandle(Arc<HandleInner>);

impl ManagedFileHandle {
    fn new(fh: vfs_fh, closer: mpsc::UnboundedSender<vfs_fh>) -> Self {
        Self(Arc::new(HandleInner { fh, closer }))
    }
}

impl Deref for ManagedFileHandle {
    type Target = vfs_fh;

    fn deref(&self) -> &vfs_fh {
        &self.0.fh
    }
}

#[derive(Debug)]
struct HandleInner {
    fh: vfs_fh,
    closer: mpsc::UnboundedSender<vfs_fh>,
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        // Unbounded: a bounded `try_send` here would silently leak the handle
        // under load, and blocking in a destructor is not an option.
        let _ = self.closer.send(self.fh);
    }
}

// --------------------------------------------------------------------- records

struct Client {
    owner: (Minor, Vec<u8>),
    verifier: verifier4,
    last_renewed: Instant,
    kind: ClientKind,
    /// This client's open state, keyed by `stateid4.other`. Owned here rather
    /// than in a server-wide map, so ownership is structural and dropping the
    /// client drops the state.
    opens: HashMap<Other, Open>,
    /// (open_owner, fileid) -> `stateid4.other`. Makes OPEN dedup O(1).
    open_index: HashMap<(Vec<u8>, fileid4), Other>,
}

impl Client {
    fn is_live(&self, now: Instant, lease: Duration) -> bool {
        now.duration_since(self.last_renewed) < lease
    }

    /// 4.0 confirms via SETCLIENTID_CONFIRM, 4.1 via CREATE_SESSION.
    fn is_confirmed(&self) -> bool {
        match &self.kind {
            ClientKind::V40(v) => v.confirmed,
            ClientKind::V41(v) => !v.sessions.is_empty(),
        }
    }

    /// This client's open-owner table, or `None` for 4.1 — which keeps no
    /// open-owner state at all, since SEQUENCE does that job. `None` is
    /// therefore also the answer to "is this a 4.1 client", and every caller
    /// that used to ask `is_v40()` really wanted this.
    fn open_owners(&self) -> Option<&HashMap<Vec<u8>, OpenOwner>> {
        match &self.kind {
            ClientKind::V40(v) => Some(&v.open_owners),
            ClientKind::V41(_) => None,
        }
    }

    fn open_owners_mut(&mut self) -> Option<&mut HashMap<Vec<u8>, OpenOwner>> {
        match &mut self.kind {
            ClientKind::V40(v) => Some(&mut v.open_owners),
            ClientKind::V41(_) => None,
        }
    }
}

/// Per-version state. Makes "4.0 client owning a session" unrepresentable.
enum ClientKind {
    V40(V40),
    V41(V41),
}

struct V40 {
    confirm_verifier: verifier4,
    confirmed: bool,
    /// Open-owner bookkeeping: sequence ordering, OPEN_CONFIRM, and the
    /// just-closed stateid a retransmitted CLOSE is routed through. It lives
    /// here rather than on `Client` so that "4.1 client accumulating
    /// open-owner state" is unrepresentable instead of merely asserted.
    open_owners: HashMap<Vec<u8>, OpenOwner>,
}

impl V40 {
    /// A record awaiting SETCLIENTID_CONFIRM.
    fn new(confirm_verifier: verifier4) -> Self {
        Self {
            confirm_verifier,
            confirmed: false,
            open_owners: HashMap::new(),
        }
    }
}

struct V41 {
    /// Next expected `csa_sequence`.
    create_session_seq: sequenceid4,
    /// In creation order; the last is the one a CREATE_SESSION replay names.
    sessions: Vec<Session>,
}

impl ClientKind {
    fn v40_mut(&mut self) -> Res<&mut V40> {
        match self {
            Self::V40(v) => Ok(v),
            Self::V41(_) => Err(nfsstat4::NFS4ERR_STALE_CLIENTID),
        }
    }

    fn v41_mut(&mut self) -> Res<&mut V41> {
        match self {
            Self::V41(v) => Ok(v),
            Self::V40(_) => Err(nfsstat4::NFS4ERR_STALE_CLIENTID),
        }
    }
}

/// NFSv4.0 open-owner: sequence ordering plus OPEN_CONFIRM.
#[derive(Default)]
struct OpenOwner {
    /// Last (seqid, reply) sent, for retransmit detection. The reply is stored
    /// whether it succeeded or failed, so a retransmit gets the same answer and
    /// a failed request still advances the mirror.
    last: Option<(seqid4, OwnerReply)>,
    /// Set by OPEN_CONFIRM. 4.1 owners are never recorded here.
    confirmed: bool,
    /// `other` of the state this owner last closed, so a retransmitted CLOSE
    /// can still be routed here. At most one; CLOSE4args carries no owner.
    retired: Option<Other>,
}

struct Session {
    id: sessionid4,
    slots: Box<[Slot]>,
    /// Negotiated `ca_maxresponsesize_cached`; bounds the reply cache.
    max_cached: u32,
}

#[derive(Clone, Default)]
struct Slot {
    /// Last sequenceid seen; 0 means never used.
    last_seqid: sequenceid4,
    /// Encoded COMPOUND4res body, when the client asked for `sa_cachethis`.
    cached: Option<Vec<u8>>,
}

/// One open state per (client, open_owner, file), as RFC 8881 §9.1.4 requires.
/// `mode` is the strongest mode ever requested; since `OpenMode` has no
/// downgrade and OPEN_DOWNGRADE is unsupported, it only ever grows.
struct Open {
    owner: Vec<u8>,
    fileid: fileid4,
    /// Stateid seqid; bumped by every state-mutating op. Never 0, because 0
    /// on the wire means "use the current seqid".
    seqid: NonZeroU32,
    mode: OpenMode,
    fh: ManagedFileHandle,
}

impl Open {
    fn bump(&mut self, other: Other) -> stateid4 {
        self.seqid = self.seqid.checked_add(1).unwrap_or(NonZeroU32::MIN);
        stateid4 {
            seqid: self.seqid.get(),
            other,
        }
    }

    fn check_seqid(&self, seqid: Option<NonZeroU32>) -> Res<()> {
        match seqid {
            None => Ok(()), // 0 == "current"
            Some(s) if s == self.seqid => Ok(()),
            Some(s) if s < self.seqid => Err(nfsstat4::NFS4ERR_OLD_STATEID),
            Some(_) => Err(nfsstat4::NFS4ERR_BAD_STATEID),
        }
    }
}

// -------------------------------------------------------------- wire → domain

/// A parsed `stateid4`. Checks and distinguishes  the two
/// special stateids, which callers must treat differently.
pub(super) enum StateRef {
    /// All-zero: anonymous access.
    Anonymous,
    /// All-ones: READ bypass.
    Bypass,
    Open {
        other: Other,
        seqid: Option<NonZeroU32>,
    },
}

impl From<&stateid4> for StateRef {
    fn from(sid: &stateid4) -> Self {
        const OTHER_ZERO: [u8; NFS4_OTHER_SIZE] = [0u8; NFS4_OTHER_SIZE];
        const OTHER_ONES: [u8; NFS4_OTHER_SIZE] = [0xffu8; NFS4_OTHER_SIZE];

        // Deliberately lenient about the seqid of special stateids: clients
        // send both 0 and ~0, and rejecting either buys nothing.
        match sid.other {
            OTHER_ZERO => Self::Anonymous,
            OTHER_ONES => Self::Bypass,
            other => Self::Open {
                other,
                seqid: NonZeroU32::new(sid.seqid),
            },
        }
    }
}

// -------------------------------------------------------------------- outcomes

pub(super) enum CreateSession {
    New(sessionid4),
    /// Replay of the CREATE_SESSION that made this session.
    Replay(sessionid4),
}

pub(super) enum Sequence {
    New,
    /// Cached COMPOUND4res body.
    Replay(Vec<u8>),
    /// Replay of a request whose reply was not cached.
    RetryUncached,
}

pub(super) struct Opened {
    pub stateid: stateid4,
    /// NFSv4.0 only: set `OPEN4_RESULT_CONFIRM`; the client must OPEN_CONFIRM.
    pub confirm_required: bool,
}

#[derive(Debug)]
pub(super) enum Resolved {
    Open {
        fileid: fileid4,
        fh: ManagedFileHandle,
        mode: OpenMode,
    },
    Anonymous,
    Bypass,
}

/// Result of the 4.0 open-owner sequence check.
#[derive(Debug, PartialEq)]
enum OwnerSeq {
    Fresh,
    /// Retransmit: hand back the recorded reply verbatim, errors included.
    Replay(OwnerReply),
}

/// What `open` decided before releasing the lock.
enum OpenPlan {
    Done(Opened),
    /// Needs `vfs::open` at this mode, then `open_commit`.
    NeedHandle(OpenMode),
}

// ----------------------------------------------------------------------- Inner

struct Inner {
    lease: Duration,
    /// Per-boot epoch in the high 32 bits of every clientid, so ids issued
    /// before a restart are reliably STALE. Also seeds the write verifier.
    epoch: u32,
    clients: HashMap<clientid4, Client>,
    unconfirmed: HashMap<(Minor, Vec<u8>), clientid4>,
    /// stateid.other -> (clientid, open_owner) for just-closed 4.0 states.
    /// One entry per open-owner; see `retire_open`.
    retired: HashMap<Other, (clientid4, Vec<u8>)>,
}

impl Inner {
    fn new(lease: Duration, epoch: u32) -> Self {
        Self {
            lease,
            epoch,
            clients: HashMap::new(),
            unconfirmed: HashMap::new(),
            retired: HashMap::new(),
        }
    }

    // -- id generation --

    fn fresh_clientid(&self) -> clientid4 {
        loop {
            let cid = ((self.epoch as u64) << 32) | getrandom::u32().expect("OS RNG failure") as u64;
            if !self.clients.contains_key(&cid) {
                break cid;
            }
        }
    }

    fn fresh_sessionid(&self) -> sessionid4 {
        let session_ids = self
            .clients
            .iter()
            .filter_map(|(_, c)| {
                if let ClientKind::V41(v41) = &c.kind {
                    Some(v41.sessions.iter().map(|s| &s.id))
                } else {
                    None
                }
            })
            .flatten()
            .collect::<Vec<_>>();

        loop {
            let mut id = [0u8; 16];
            getrandom::fill(&mut id).expect("OS RNG failure");
            if !session_ids.contains(&&id) {
                break id;
            }
        }
    }

    /// Avoids both live and just-retired states, so a retransmitted CLOSE can
    /// never be misrouted to a fresh open that happened to reuse the bytes.
    fn fresh_other(&self) -> Other {
        let others = self
            .clients
            .iter()
            .map(|(_, c)| c.opens.iter().map(|(o, _)| o))
            .flatten()
            .collect::<Vec<_>>();

        loop {
            let mut other = [0u8; NFS4_OTHER_SIZE];
            getrandom::fill(&mut other).expect("OS RNG failure");
            if !others.contains(&&other) && !self.retired.contains_key(&other) {
                break other;
            }
        }
    }

    // -- client lookup and expiry --

    /// Resolve a live client, expiring it first if its lease has lapsed.
    fn client_mut(&mut self, cid: clientid4, now: Instant) -> Res<&mut Client> {
        match self.clients.get(&cid) {
            None => return Err(nfsstat4::NFS4ERR_STALE_CLIENTID),
            Some(c) if c.is_live(now, self.lease) => {},
            Some(_) => {
                self.remove_client(cid);
                return Err(nfsstat4::NFS4ERR_EXPIRED);
            },
        }
        Ok(self.clients.get_mut(&cid).expect("just checked"))
    }

    /// Drop a client and everything it owns. Dropping the open states closes
    /// their handles via the background closer.
    fn remove_client(&mut self, cid: clientid4) {
        let Some(client) = self.clients.remove(&cid) else {
            return;
        };
        if self.unconfirmed.get(&client.owner) == Some(&cid) {
            self.unconfirmed.remove(&client.owner);
        }
        if let Some(owners) = client.open_owners() {
            for owner in owners.values() {
                if let Some(other) = owner.retired {
                    self.retired.remove(&other);
                }
            }
        }
    }

    /// The *current* client registered under `owner`, ignoring any pending
    /// SETCLIENTID attempt.
    ///
    /// A 4.0 owner legitimately has two records between SETCLIENTID and
    /// SETCLIENTID_CONFIRM (RFC 7530 §16.33.5): the confirmed incarnation that
    /// still owns the open state, and the unconfirmed one that will replace it.
    /// `clients` is a HashMap, so a search that considers both returns whichever
    /// key hashes first — which made both callers order-dependent: SETCLIENTID
    /// could hand back the *pending* record as though it were confirmed, and
    /// SETCLIENTID_CONFIRM's `old != cid` guard could match the record it had
    /// just confirmed and so never retire the previous incarnation, leaking its
    /// open state and VFS handles.
    ///
    /// The pending record is identified by the `unconfirmed` index rather than
    /// by `is_confirmed()`: a 4.1 record counts as unconfirmed until
    /// CREATE_SESSION, but it is still the only record for its owner and
    /// EXCHANGE_ID must keep finding it.
    fn by_owner(&self, owner: &(Minor, Vec<u8>)) -> Option<clientid4> {
        let pending = self.unconfirmed.get(owner).copied();
        self.clients
            .iter()
            .find_map(|(id, c)| (&c.owner == owner && Some(*id) != pending).then_some(*id))
    }

    /// Create a record without touching any existing record for `owner` and
    /// without indexing it; the caller decides which index it belongs in.
    fn add_client(
        &mut self,
        owner: (Minor, Vec<u8>),
        verifier: verifier4,
        kind: ClientKind,
        now: Instant,
    ) -> clientid4 {
        let cid = self.fresh_clientid();
        self.clients.insert(
            cid,
            Client {
                owner,
                verifier,
                last_renewed: now,
                kind,
                opens: HashMap::new(),
                open_index: HashMap::new(),
            },
        );
        cid
    }

    /// Replace any confirmed client registered under `owner`, then insert a
    /// fresh confirmed record.
    fn install_client(
        &mut self,
        owner: (Minor, Vec<u8>),
        verifier: verifier4,
        kind: ClientKind,
        now: Instant,
    ) -> clientid4 {
        if let Some(old) = self.by_owner(&owner) {
            self.remove_client(old);
        }
        self.add_client(owner.clone(), verifier, kind, now)
    }

    fn sweep_expired(&mut self, now: Instant) {
        let dead: Vec<clientid4> = self
            .clients
            .iter()
            .filter(|(_, c)| !c.is_live(now, self.lease))
            .map(|(cid, _)| *cid)
            .collect();
        for cid in dead {
            self.remove_client(cid);
        }
    }

    fn open(&self, cid: clientid4, other: &Other) -> Res<&Open> {
        self.clients
            .get(&cid)
            .and_then(|c| c.opens.get(other))
            .ok_or(nfsstat4::NFS4ERR_BAD_STATEID)
    }

    fn open_mut(&mut self, cid: clientid4, other: &Other) -> Res<&mut Open> {
        self.clients
            .get_mut(&cid)
            .and_then(|c| c.opens.get_mut(other))
            .ok_or(nfsstat4::NFS4ERR_BAD_STATEID)
    }

    /// The `Session` named by `sessionid`, resolved through the locator into
    /// the client that owns it.
    fn session_mut(&mut self, cid: clientid4, sessionid: &sessionid4) -> Res<&mut Session> {
        let client = self.clients.get_mut(&cid).ok_or(nfsstat4::NFS4ERR_BADSESSION)?;
        match &mut client.kind {
            ClientKind::V41(v) => v.sessions.iter_mut().find(|s| s.id == *sessionid),
            ClientKind::V40(_) => None,
        }
        .ok_or(nfsstat4::NFS4ERR_BADSESSION)
    }

    // -- 4.0 open-owner sequencing --

    /// The open-owner seqid that actually governs this request, or `None` when
    /// there is none.
    ///
    /// The answer comes from the *client record*, not from the argument: a 4.1
    /// client's OPEN/CLOSE seqid must be ignored (RFC 8881 §18.16.1), and a
    /// dispatcher that forwards the wire field verbatim must not be able to
    /// turn a 4.1 CLOSE into a phantom replay.
    fn owner_seqid_for(&self, cid: clientid4, seqid: OwnerSeqid) -> Res<Option<seqid4>> {
        let client = self.clients.get(&cid).ok_or(nfsstat4::NFS4ERR_STALE_CLIENTID)?;
        match (&client.kind, seqid) {
            (ClientKind::V40(_), OwnerSeqid::V40(s)) => Ok(Some(s)),
            // 4.1: SEQUENCE already de-duplicated this request.
            (ClientKind::V41(_), _) => Ok(None),
            (ClientKind::V40(_), OwnerSeqid::V41) => {
                debug_assert!(false, "4.0 request reached state without an open-owner seqid");
                Err(nfsstat4::NFS4ERR_INVAL)
            },
        }
    }

    fn check_owner_seqid(&self, cid: clientid4, owner: &[u8], seqid: OwnerSeqid) -> Res<OwnerSeq> {
        let Some(seqid) = self.owner_seqid_for(cid, seqid)? else {
            return Ok(OwnerSeq::Fresh);
        };
        let client = self.clients.get(&cid).expect("owner_seqid_for resolved it");
        // `owner_seqid_for` yielded a seqid, so this is a 4.0 client.
        let last = client
            .open_owners()
            .and_then(|owners| owners.get(owner))
            .and_then(|o| o.last.as_ref());
        match last {
            None => Ok(OwnerSeq::Fresh),
            Some((last, reply)) if seqid == *last => Ok(OwnerSeq::Replay(reply.clone())),
            Some((last, _)) if seqid == last.wrapping_add(1) => Ok(OwnerSeq::Fresh),
            Some(_) => Err(nfsstat4::NFS4ERR_BAD_SEQID),
        }
    }

    /// Record the reply this request produced, so a retransmit replays it and
    /// the mirror stays level with the client's counter. Statuses on
    /// `seqid_retained`'s list did not consume a seqid, so they are not stored.
    fn record_owner_reply(&mut self, cid: clientid4, owner: &[u8], seqid: OwnerSeqid, reply: OwnerReply) {
        let OwnerSeqid::V40(seqid) = seqid else { return };
        if matches!(&reply, Err(e) if seqid_retained(e)) {
            return;
        }
        // Absent for a client that has gone away, or a 4.1 one.
        let Some(owners) = self.clients.get_mut(&cid).and_then(Client::open_owners_mut) else {
            return;
        };
        owners.entry(owner.to_vec()).or_default().last = Some((seqid, reply));
    }

    /// A request that consumed the seqid without producing a stateid. Returns
    /// `status` unchanged so callers can `return Err(...)` in one line.
    fn record_owner_failure(&mut self, cid: clientid4, owner: &[u8], seqid: OwnerSeqid, status: nfsstat4) -> nfsstat4 {
        self.record_owner_reply(cid, owner, seqid, Err(status));
        status
    }

    /// Run `f` under this open-owner's sequencing: replay a retransmit,
    /// otherwise record whatever reply comes back. The single choke point for
    /// ops that both consume a seqid and return a stateid.
    fn with_owner_seqid(
        &mut self,
        cid: clientid4,
        owner: &[u8],
        seqid: OwnerSeqid,
        f: impl FnOnce(&mut Self) -> Res<stateid4>,
    ) -> Res<stateid4> {
        if let OwnerSeq::Replay(cached) = self.check_owner_seqid(cid, owner, seqid)? {
            return cached;
        }
        let reply = f(self);
        self.record_owner_reply(cid, owner, seqid, reply.clone());
        reply
    }

    /// An op that names an open-owner but which this server does not implement
    /// (OPEN_DOWNGRADE, LOCK's `open_to_lock_owner4`). Rejecting it still
    /// consumes the client's seqid unless the status says otherwise, so it has
    /// to be booked like any other reply.
    fn note_owner_rejection(
        &mut self,
        cid: clientid4,
        owner: &[u8],
        seqid: OwnerSeqid,
        status: nfsstat4,
        now: Instant,
    ) -> nfsstat4 {
        if self.client_mut(cid, now).is_err() {
            return status;
        }
        match self.check_owner_seqid(cid, owner, seqid) {
            // Retransmit of the same rejected op: repeat it, do not advance.
            Ok(OwnerSeq::Replay(Err(cached))) => cached,
            Ok(OwnerSeq::Replay(Ok(_))) => status,
            Ok(OwnerSeq::Fresh) => self.record_owner_failure(cid, owner, seqid, status),
            Err(e) => e,
        }
    }

    /// 4.1 has no OPEN_CONFIRM; 4.0 needs it once per open-owner.
    fn confirm_required(&self, cid: clientid4, owner: &[u8]) -> bool {
        let Some(client) = self.clients.get(&cid) else {
            return false;
        };
        client
            .open_owners()
            .is_some_and(|owners| !owners.get(owner).is_some_and(|o| o.confirmed))
    }

    // -- OPEN, in three phases --

    /// Phase 1: everything decidable without touching the VFS.
    fn open_plan(
        &mut self,
        cid: clientid4,
        owner: &[u8],
        owner_seqid: OwnerSeqid,
        fileid: fileid4,
        mode: OpenMode,
        now: Instant,
    ) -> Res<OpenPlan> {
        let client = self.client_mut(cid, now)?;
        if !client.is_confirmed() {
            return Err(nfsstat4::NFS4ERR_STALE_CLIENTID);
        }
        client.last_renewed = now;

        if let OwnerSeq::Replay(cached) = self.check_owner_seqid(cid, owner, owner_seqid)? {
            return Ok(OpenPlan::Done(Opened {
                // A replayed failure is still a failure.
                stateid: cached?,
                // The original reply was lost, so repeat the flag it carried
                // rather than silently dropping it.
                confirm_required: self.confirm_required(cid, owner),
            }));
        }

        // Reuse the existing state if its handle is already strong enough.
        let reuse = {
            let client = self.clients.get_mut(&cid).expect("still live");
            match client.open_index.get(&(owner.to_vec(), fileid)).copied() {
                Some(other) => {
                    let open = client.opens.get_mut(&other).expect("open_index points into opens");
                    (open.mode >= mode).then(|| open.bump(other))
                },
                None => None,
            }
        };
        if let Some(stateid) = reuse {
            return Ok(OpenPlan::Done(self.finish_open(cid, owner, owner_seqid, stateid)));
        }
        Ok(OpenPlan::NeedHandle(mode))
    }

    /// Phase 3: install a freshly opened handle. Tolerates a concurrent OPEN
    /// having won the race — the redundant handle is simply dropped and closed.
    fn open_commit(
        &mut self,
        cid: clientid4,
        owner: &[u8],
        owner_seqid: OwnerSeqid,
        fileid: fileid4,
        mode: OpenMode,
        fh: ManagedFileHandle,
        now: Instant,
    ) -> Res<Opened> {
        self.client_mut(cid, now)?;

        let key = (owner.to_vec(), fileid);
        let existing = self.clients[&cid].open_index.get(&key).copied();
        let stateid = match existing {
            Some(other) => {
                let open = self.open_mut(cid, &other).expect("open_index points into opens");
                if mode > open.mode {
                    open.mode = mode;
                    open.fh = fh; // the superseded handle closes on drop
                }
                open.bump(other)
            },
            None => {
                let other = self.fresh_other();
                let client = self.clients.get_mut(&cid).expect("still live");
                client.opens.insert(
                    other,
                    Open {
                        owner: owner.to_vec(),
                        fileid,
                        seqid: NonZeroU32::MIN,
                        mode,
                        fh,
                    },
                );
                client.open_index.insert(key, other);
                stateid4 { seqid: 1, other }
            },
        };
        Ok(self.finish_open(cid, owner, owner_seqid, stateid))
    }

    fn finish_open(&mut self, cid: clientid4, owner: &[u8], owner_seqid: OwnerSeqid, stateid: stateid4) -> Opened {
        self.record_owner_reply(cid, owner, owner_seqid, Ok(stateid));
        Opened {
            stateid,
            confirm_required: self.confirm_required(cid, owner),
        }
    }

    // -- OPEN_CONFIRM and CLOSE --

    /// OPEN_CONFIRM. 4.0 only.
    fn open_confirm(&mut self, cid: clientid4, sid: &stateid4, owner_seqid: seqid4, now: Instant) -> Res<stateid4> {
        let StateRef::Open { other, seqid } = StateRef::from(sid) else {
            return Err(nfsstat4::NFS4ERR_BAD_STATEID);
        };
        let owner = self.open(cid, &other)?.owner.clone();
        let client = self.client_mut(cid, now)?;
        client.kind.v40_mut()?; // there is no OPEN_CONFIRM in 4.1
        client.last_renewed = now;

        // The open-owner seqid is checked *before* the stateid (RFC 7530
        // §9.1.7): this op bumps the stateid, so a retransmit necessarily
        // carries the now-superseded one and must replay rather than draw
        // NFS4ERR_OLD_STATEID. On a genuinely fresh seqid the stateid check
        // below still applies, and that failure consumes the seqid —
        // OLD_STATEID is not on `seqid_retained`'s list.
        self.with_owner_seqid(cid, &owner, OwnerSeqid::V40(owner_seqid), |s| {
            let open = s.open_mut(cid, &other)?;
            open.check_seqid(seqid)?;
            let stateid = open.bump(other);
            s.clients
                .get_mut(&cid)
                .expect("still live")
                .open_owners_mut()
                .expect("v40_mut succeeded above")
                .entry(owner.clone())
                .or_default()
                .confirmed = true;
            Ok(stateid)
        })
    }

    // -- 4.0 client establishment --

    /// SETCLIENTID (RFC 7530 §16.33.5).
    ///
    /// A confirmed record whose verifier still matches means the client did
    /// *not* reboot — this is a retransmit, a reconnect, or a callback update.
    /// It keeps its clientid and, crucially, all of its open state; only the
    /// confirm verifier is re-armed. Minting a new clientid and purging state
    /// here made every reconnect look like a reboot and silently closed the
    /// client's files underneath it.
    fn setclientid(&mut self, ownerid: &[u8], verifier: &verifier4, now: Instant) -> (clientid4, verifier4) {
        let owner = (Minor::V40, ownerid.to_vec());

        let mut confirm = verifier4::default();
        getrandom::fill(&mut confirm).expect("OS RNG failure");

        // Any earlier unconfirmed attempt is superseded. It can own no state:
        // `open_plan` rejects unconfirmed clients.
        if let Some(&stale) = self.unconfirmed.get(&owner) {
            self.remove_client(stale);
        }

        if let Some(cid) = self.by_owner(&owner) {
            if self
                .clients
                .get(&cid)
                .is_some_and(|c| c.verifier == *verifier && c.is_confirmed())
            {
                let client = self.clients.get_mut(&cid).expect("just checked");
                client.last_renewed = now;
                client.kind.v40_mut().expect("keyed by minor version").confirm_verifier = confirm;
                return (cid, confirm);
            }
        }

        // New client, or one whose verifier changed (reboot). The previous
        // incarnation's state survives until SETCLIENTID_CONFIRM proves it.
        let kind = ClientKind::V40(V40::new(confirm));
        let cid = self.add_client(owner.clone(), *verifier, kind, now);
        self.unconfirmed.insert(owner, cid);
        (cid, confirm)
    }

    /// SETCLIENTID_CONFIRM (RFC 7530 §16.34.5). Idempotent: confirming an
    /// already-confirmed record is a retransmit and must not disturb state.
    fn setclientid_confirm(&mut self, cid: clientid4, confirm: &verifier4, now: Instant) -> Res<()> {
        let (owner, already) = {
            let client = self.client_mut(cid, now)?;
            let owner = client.owner.clone();
            let v40 = client.kind.v40_mut()?;
            if v40.confirm_verifier != *confirm {
                return Err(nfsstat4::NFS4ERR_STALE_CLIENTID);
            }
            let already = v40.confirmed;
            v40.confirmed = true;
            client.last_renewed = now;
            (owner, already)
        };

        if !already {
            // The reboot is now proven, so — and only now — the previous
            // incarnation and its state go away. `by_owner` must be consulted
            // while this record is still in `unconfirmed`, so that it masks
            // this record and can only return the incarnation being replaced.
            if let Some(old) = self.by_owner(&owner) {
                if old != cid {
                    self.remove_client(old);
                }
            }
            self.unconfirmed.remove(&owner);
        }
        Ok(())
    }

    /// CLOSE. Releases the whole open state and returns the bumped stateid.
    /// Dropping the `Open` hands its handle to the background closer, so the
    /// replay short-circuit must only fire for a genuine 4.0 retransmit.
    fn close(&mut self, cid: clientid4, sid: &stateid4, owner_seqid: OwnerSeqid, now: Instant) -> Res<stateid4> {
        let StateRef::Open { other, seqid } = StateRef::from(sid) else {
            return Err(nfsstat4::NFS4ERR_BAD_STATEID);
        };

        // The state may already be gone: a retransmitted CLOSE must still reach
        // the open-owner record, and CLOSE4args names no owner of its own.
        let owner = self.owner_of(cid, &other)?;
        self.client_mut(cid, now)?.last_renewed = now;

        self.with_owner_seqid(cid, &owner, owner_seqid, |s| {
            // Fresh seqid on a state that is already closed: nothing to release.
            let open = s.open_mut(cid, &other)?;
            open.check_seqid(seqid)?;
            let stateid = open.bump(other);
            s.remove_open(cid, &other);
            s.retire_open(cid, &owner, other);
            Ok(stateid)
        })
    }

    /// The open-owner of `other`, live or just-retired - but only if `cid`
    /// actually owns it.
    fn owner_of(&self, cid: clientid4, other: &Other) -> Res<Vec<u8>> {
        if let Ok(open) = self.open(cid, other) {
            return Ok(open.owner.clone());
        }
        match self.retired.get(other) {
            Some((holder, owner)) if *holder == cid => Ok(owner.clone()),
            _ => Err(nfsstat4::NFS4ERR_BAD_STATEID),
        }
    }

    fn resolve(&mut self, cid: clientid4, sid: &stateid4, now: Instant) -> Res<Resolved> {
        match StateRef::from(sid) {
            StateRef::Anonymous => Ok(Resolved::Anonymous),
            StateRef::Bypass => Ok(Resolved::Bypass),
            StateRef::Open { other, seqid } => {
                let open = self.open(cid, &other)?;
                open.check_seqid(seqid)?;
                let resolved = Resolved::Open {
                    fileid: open.fileid,
                    fh: open.fh.clone(),
                    mode: open.mode,
                };
                self.client_mut(cid, now)?.last_renewed = now;
                Ok(resolved)
            },
        }
    }

    fn remove_open(&mut self, cid: clientid4, other: &Other) {
        if let Some(client) = self.clients.get_mut(&cid) {
            if let Some(open) = client.opens.remove(other) {
                client.open_index.remove(&(open.owner, open.fileid));
            }
        }
    }

    /// Record `other` as this open-owner's just-closed state, replacing any
    /// earlier one. 4.0 only: 4.1 replays a retransmitted CLOSE from the slot
    /// cache and keeps no open-owner state at all.
    fn retire_open(&mut self, cid: clientid4, owner: &[u8], other: Other) {
        let previous = {
            // 4.1 replays a retransmitted CLOSE from the slot cache, so it
            // needs no tombstone and has nowhere to put one.
            let Some(owners) = self.clients.get_mut(&cid).and_then(Client::open_owners_mut) else {
                return;
            };
            owners.entry(owner.to_vec()).or_default().retired.replace(other)
        };
        if let Some(prev) = previous {
            self.retired.remove(&prev);
        }
        self.retired.insert(other, (cid, owner.to_vec()));
    }

    /// OPEN_DOWNGRADE (RFC 7530 §16.19).
    fn open_downgrade(
        &mut self,
        cid: clientid4,
        sid: &stateid4,
        owner_seqid: OwnerSeqid,
        now: Instant,
    ) -> Res<stateid4> {
        let StateRef::Open { other, seqid } = StateRef::from(sid) else {
            return Err(nfsstat4::NFS4ERR_BAD_STATEID);
        };
        let owner = self.owner_of(cid, &other)?;
        self.client_mut(cid, now)?.last_renewed = now;

        self.with_owner_seqid(cid, &owner, owner_seqid, |s| {
            let open = s.open_mut(cid, &other)?;
            open.check_seqid(seqid)?;
            Ok(open.bump(other))
        })
    }

    /// `note_owner_rejection` for an op that names its open-owner only through
    /// a stateid (LOCK's `open_to_lock_owner4`).
    fn note_stateid_rejection(
        &mut self,
        cid: clientid4,
        sid: &stateid4,
        owner_seqid: OwnerSeqid,
        status: nfsstat4,
        now: Instant,
    ) -> nfsstat4 {
        let StateRef::Open { other, .. } = StateRef::from(sid) else {
            return nfsstat4::NFS4ERR_BAD_STATEID; // retained: consumes nothing
        };
        match self.owner_of(cid, &other) {
            Ok(owner) => self.note_owner_rejection(cid, &owner, owner_seqid, status, now),
            Err(e) => e,
        }
    }
}

#[cfg(test)]
impl Inner {
    fn open_of(&self, other: &Other) -> &Open {
        self.clients.iter().find_map(|(_, c)| c.opens.get(other)).unwrap()
    }

    fn open_of_mut(&mut self, other: &Other) -> &mut Open {
        self.clients.iter_mut().find_map(|(_, c)| c.opens.get_mut(other)).unwrap()
    }

    fn open_index_len(&self) -> usize {
        self.clients.values().map(|c| c.open_index.len()).sum()
    }

    fn sessions(&self) -> Vec<&Session> {
        self.clients
            .iter()
            .filter_map(|(_, c)| {
                if let ClientKind::V41(v41) = &c.kind {
                    Some(v41.sessions.iter())
                } else {
                    None
                }
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    fn opens(&self) -> Vec<&Open> {
        self.clients.iter().map(|(_, c)| c.opens.values()).flatten().collect()
    }

    fn assert_invariants(&self) {
        for (_, client) in &self.clients {
            for (other, open) in &client.opens {
                assert_eq!(
                    client.open_index.get(&(open.owner.clone(), open.fileid)),
                    Some(other),
                    "open_index out of sync"
                );
            }
            assert_eq!(client.open_index.len(), client.opens.len());
        }
        for (other, (cid, owner)) in &self.retired {
            let client = self.clients.get(cid).expect("orphaned retired stateid");
            let owners = client.open_owners().expect("4.1 keeps no retired stateids");
            assert_eq!(owners.get(owner).and_then(|o| o.retired), Some(*other), "retired index out of sync");
            assert!(self.open(*cid, other).is_err(), "retired stateid is still live");
        }
        for (owner, cid) in &self.unconfirmed {
            assert_eq!(self.clients.get(cid).map(|c| &c.owner), Some(owner), "unconfirmed out of sync");
            assert!(!self.clients[cid].is_confirmed(), "confirmed client in the unconfirmed index");
            assert_ne!(self.by_owner(owner), Some(*cid), "record cannot be in both indexes");
        }

        // At most one *current* record per owner, plus at most one pending
        // SETCLIENTID attempt. Two current records would make `by_owner`
        // depend on HashMap iteration order again.
        let mut current: HashMap<&(Minor, Vec<u8>), usize> = HashMap::new();
        for (cid, client) in &self.clients {
            if self.unconfirmed.get(&client.owner) == Some(cid) {
                continue;
            }
            *current.entry(&client.owner).or_default() += 1;
        }
        assert!(current.values().all(|n| *n == 1), "two current records for one client owner");
    }
}

// ------------------------------------------------------------------ NFS4State

pub struct NFS4State {
    inner: Arc<Mutex<Inner>>,
    vfs: Arc<dyn NFSFileSystem + Send + Sync>,
    closer_tx: mpsc::UnboundedSender<vfs_fh>,
    reaper: JoinHandle<()>,
    closer: JoinHandle<()>,
}

impl Drop for NFS4State {
    fn drop(&mut self) {
        self.reaper.abort();
        self.closer.abort();
    }
}

impl NFS4State {
    pub(crate) fn new(lease: Duration, vfs: Arc<dyn NFSFileSystem + Send + Sync>, epoch: u32) -> Self {
        let inner = Arc::new(Mutex::new(Inner::new(lease, epoch)));
        let (closer_tx, mut closer_rx) = mpsc::unbounded_channel::<vfs_fh>();

        let closer = {
            let vfs = vfs.clone();
            tokio::spawn(async move {
                while let Some(fh) = closer_rx.recv().await {
                    let _ = vfs.close(fh).await;
                }
            })
        };

        let reaper = {
            let inner = inner.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(REAP_INTERVAL).await;
                    inner.lock().unwrap().sweep_expired(Instant::now());
                }
            })
        };

        Self {
            inner,
            vfs,
            closer_tx,
            reaper,
            closer,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    // -- NFSv4.1: clientid and sessions --

    /// EXCHANGE_ID. Returns the clientid and the next CREATE_SESSION sequenceid.
    /// A changed verifier means the client rebooted, so its old state is dropped.
    pub(super) fn exchange_id(&self, ownerid: &[u8], verifier: &verifier4) -> (clientid4, sequenceid4) {
        let now = Instant::now();
        let mut g = self.lock();
        let owner = (Minor::V41, ownerid.to_vec());

        if let Some(cid) = g.by_owner(&owner) {
            let client = &g.clients[&cid];
            if client.verifier == *verifier && client.is_live(now, g.lease) {
                let seq = match &client.kind {
                    ClientKind::V41(v) => v.create_session_seq,
                    ClientKind::V40(_) => unreachable!("keyed by minor version"),
                };
                return (cid, seq);
            }
        }

        let kind = ClientKind::V41(V41 {
            create_session_seq: 1,
            sessions: Vec::new(),
        });
        (g.install_client(owner, *verifier, kind, now), 1)
    }

    /// CREATE_SESSION. `num_slots` is the requested `ca_maxrequests`,
    /// `max_cached` the negotiated `ca_maxresponsesize_cached`.
    pub(super) fn create_session(
        &self,
        cid: clientid4,
        csa_sequence: sequenceid4,
        num_slots: u32,
        max_cached: u32,
    ) -> Res<CreateSession> {
        let now = Instant::now();
        let mut g = self.lock();

        let client = g.client_mut(cid, now)?;
        client.last_renewed = now;
        let v41 = client.kind.v41_mut()?;
        let expected = v41.create_session_seq;
        let last = v41.sessions.last().map(|s| s.id);

        if csa_sequence == expected.wrapping_sub(1) {
            // Replay of the previous CREATE_SESSION.
            return last.map(CreateSession::Replay).ok_or(nfsstat4::NFS4ERR_SEQ_MISORDERED);
        }
        if csa_sequence != expected {
            return Err(nfsstat4::NFS4ERR_SEQ_MISORDERED);
        }

        let sessionid = g.fresh_sessionid();
        let slots = vec![Slot::default(); num_slots.clamp(1, MAX_SLOTS) as usize].into_boxed_slice();

        let v41 = g.clients.get_mut(&cid).expect("still live").kind.v41_mut()?;
        v41.create_session_seq = expected.wrapping_add(1);
        v41.sessions.push(Session {
            id: sessionid,
            slots,
            max_cached,
        });
        Ok(CreateSession::New(sessionid))
    }

    /// SEQUENCE slot check. Renews the lease on any accepted request.
    pub(super) fn sequence(
        &self,
        cid: clientid4,
        sessionid: &sessionid4,
        slotid: slotid4,
        seqid: sequenceid4,
    ) -> Res<Sequence> {
        let now = Instant::now();
        let mut g = self.lock();

        // An expired client takes its sessions with it.
        g.client_mut(cid, now).map_err(|_| nfsstat4::NFS4ERR_BADSESSION)?;

        let session = g.session_mut(cid, sessionid)?;
        let slot = session.slots.get_mut(slotid as usize).ok_or(nfsstat4::NFS4ERR_BADSLOT)?;

        let outcome = if seqid == slot.last_seqid {
            match &slot.cached {
                Some(reply) => Sequence::Replay(reply.clone()),
                None => Sequence::RetryUncached,
            }
        } else if seqid == slot.last_seqid.wrapping_add(1) {
            slot.last_seqid = seqid;
            slot.cached = None;
            Sequence::New
        } else {
            return Err(nfsstat4::NFS4ERR_SEQ_MISORDERED);
        };

        g.clients.get_mut(&cid).expect("still live").last_renewed = now;
        Ok(outcome)
    }

    /// Cache an encoded COMPOUND4res for a slot (`sa_cachethis`). Oversized
    /// replies are dropped; a replay then gets `RetryUncached`.
    pub(super) fn cache_reply(
        &self,
        cid: clientid4,
        sessionid: &sessionid4,
        slotid: slotid4,
        seqid: sequenceid4,
        reply: Vec<u8>,
    ) {
        let mut g = self.lock();
        let Ok(session) = g.session_mut(cid, sessionid) else {
            return;
        };

        if reply.len() as u64 > session.max_cached as u64 {
            return;
        }
        if let Some(slot) = session.slots.get_mut(slotid as usize) {
            if slot.last_seqid == seqid {
                slot.cached = Some(reply);
            }
        }
    }

    /// DESTROY_SESSION.
    pub(super) fn destroy_session(&self, cid: clientid4, sessionid: &sessionid4) -> Res<()> {
        let mut g = self.lock();
        if let Some(ClientKind::V41(v)) = g.clients.get_mut(&cid).map(|c| &mut c.kind) {
            v.sessions.retain(|s| s.id != *sessionid);
        }
        Ok(())
    }

    /// DESTROY_CLIENTID.
    pub(super) fn destroy_clientid(&self, cid: clientid4) -> Res<()> {
        let mut g = self.lock();
        let client = g.clients.get(&cid).ok_or(nfsstat4::NFS4ERR_STALE_CLIENTID)?;
        if matches!(&client.kind, ClientKind::V41(v) if !v.sessions.is_empty()) {
            return Err(nfsstat4::NFS4ERR_CLIENTID_BUSY);
        }
        g.remove_client(cid);
        Ok(())
    }

    /// RECLAIM_COMPLETE. Nothing to reclaim without persistent state, so this
    /// only validates the session and renews the lease. OPEN must therefore
    /// always reject CLAIM_PREVIOUS with NFS4ERR_NO_GRACE.
    pub(super) fn reclaim_complete(&self, cid: clientid4, sessionid: &sessionid4) -> Res<()> {
        let now = Instant::now();
        let mut g = self.lock();
        let client = g.clients.get(&cid).ok_or(nfsstat4::NFS4ERR_STALE_CLIENTID)?;
        if let ClientKind::V41(v41) = &client.kind {
            if v41.sessions.iter().find(|s| &s.id == sessionid).is_none() {
                return Err(nfsstat4::NFS4ERR_BADSESSION);
            }
        }
        g.client_mut(cid, now)?.last_renewed = now;
        Ok(())
    }

    // -- NFSv4.0: clientid --

    /// SETCLIENTID. A retry from an unrebooted client returns its existing
    /// clientid and preserves its open state.
    pub(super) fn setclientid(&self, ownerid: &[u8], verifier: &verifier4) -> (clientid4, verifier4) {
        self.lock().setclientid(ownerid, verifier, Instant::now())
    }

    /// SETCLIENTID_CONFIRM. Idempotent, so retransmits succeed.
    pub(super) fn setclientid_confirm(&self, cid: clientid4, confirm: &verifier4) -> Res<()> {
        self.lock().setclientid_confirm(cid, confirm, Instant::now())
    }

    /// RENEW.
    pub(super) fn renew(&self, cid: clientid4) -> Res<()> {
        let now = Instant::now();
        let mut g = self.lock();
        g.client_mut(cid, now)?.last_renewed = now;
        Ok(())
    }

    /// OPEN_CONFIRM. 4.0 only; a 4.1 client gets NFS4ERR_STALE_CLIENTID.
    pub(super) fn open_confirm(&self, cid: clientid4, sid: &stateid4, owner_seqid: seqid4) -> Res<stateid4> {
        self.lock().open_confirm(cid, sid, owner_seqid, Instant::now())
    }

    // -- open state --

    /// OPEN. `owner_seqid` must be derived from the negotiated minor version:
    /// `OwnerSeqid::V40(args.seqid)` for 4.0, `OwnerSeqid::V41` for 4.1.
    pub(super) async fn open(
        &self,
        cid: clientid4,
        owner: &[u8],
        owner_seqid: OwnerSeqid,
        fileid: fileid4,
        mode: OpenMode,
    ) -> Res<Opened> {
        // Phase 1: decide under the lock.
        let mode = match self.lock().open_plan(cid, owner, owner_seqid, fileid, mode, Instant::now())? {
            OpenPlan::Done(opened) => return Ok(opened),
            OpenPlan::NeedHandle(mode) => mode,
        };

        // Phase 2: the one unavoidable await. The lock is released, so a
        // concurrent OPEN of the same file may also get here; phase 3 folds
        // the loser's handle away instead of leaking it.
        let fh = match self.vfs.open(fileid, mode).await {
            Ok(fh) => ManagedFileHandle::new(fh, self.closer_tx.clone()),
            Err(e) => {
                // The failed OPEN consumed the client's seqid all the same.
                let status = nfsstat4::from(e);
                return Err(self.lock().record_owner_failure(cid, owner, owner_seqid, status));
            },
        };

        // Phase 3: install.
        match self
            .lock()
            .open_commit(cid, owner, owner_seqid, fileid, mode, fh, Instant::now())
        {
            Ok(opened) => Ok(opened),
            Err(status) => Err(self.lock().record_owner_failure(cid, owner, owner_seqid, status)),
        }
    }

    /// Resolve a stateid for READ/WRITE/etc.
    pub(super) fn resolve(&self, cid: clientid4, sid: &stateid4) -> Res<Resolved> {
        self.lock().resolve(cid, sid, Instant::now())
    }

    /// CLOSE. Releases the whole open state and returns the bumped stateid.
    pub(super) fn close(&self, cid: clientid4, sid: &stateid4, owner_seqid: OwnerSeqid) -> Res<stateid4> {
        self.lock().close(cid, sid, owner_seqid, Instant::now())
    }

    /// Reject an op that names an open-owner but which this server does not
    /// implement — OPEN_DOWNGRADE, and LOCK's `open_to_lock_owner4`.
    ///
    /// The dispatcher **must** route those through here rather than returning
    /// the status directly: NFS4ERR_NOTSUPP is not on RFC 7530 §9.1.7's retain
    /// list, so the client advances its open-owner seqid anyway, and a server
    /// that does not follow suit answers the client's *next* OPEN or CLOSE with
    /// NFS4ERR_BAD_SEQID and never recovers.
    pub(super) fn reject_owner_op(
        &self,
        cid: clientid4,
        owner: &[u8],
        owner_seqid: OwnerSeqid,
        status: nfsstat4,
    ) -> nfsstat4 {
        self.lock()
            .note_owner_rejection(cid, owner, owner_seqid, status, Instant::now())
    }

    /// TEST_STATEID: per-stateid status.
    pub(super) fn test_stateid(&self, cid: clientid4, sid: &stateid4) -> nfsstat4 {
        match self.resolve(cid, sid) {
            Ok(_) => nfsstat4::NFS4_OK,
            Err(e) => e,
        }
    }

    /// OPEN_DOWNGRADE. 4.0 only in practice; 4.1 passes `OwnerSeqid::V41`.
    pub(super) fn open_downgrade(&self, cid: clientid4, sid: &stateid4, owner_seqid: OwnerSeqid) -> Res<stateid4> {
        self.lock().open_downgrade(cid, sid, owner_seqid, Instant::now())
    }

    /// As `reject_owner_op`, for an op that identifies the open-owner by stateid.
    pub(super) fn reject_stateid_owner_op(
        &self,
        cid: clientid4,
        sid: &stateid4,
        owner_seqid: OwnerSeqid,
        status: nfsstat4,
    ) -> nfsstat4 {
        self.lock()
            .note_stateid_rejection(cid, sid, owner_seqid, status, Instant::now())
    }
}

// --------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    const LEASE: Duration = Duration::from_secs(90);

    fn handle() -> ManagedFileHandle {
        // The receiver is dropped; the send in HandleInner::drop just fails.
        let (tx, _) = mpsc::unbounded_channel();
        ManagedFileHandle::new(7, tx)
    }

    /// A handle whose closer channel the test keeps, so it can assert that the
    /// handle really was handed over to be closed.
    fn tracked_handle(fh: vfs_fh) -> (ManagedFileHandle, mpsc::UnboundedReceiver<vfs_fh>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (ManagedFileHandle::new(fh, tx), rx)
    }

    fn inner() -> Inner {
        Inner::new(LEASE, getrandom::u32().expect("OS RNG failure"))
    }

    /// A confirmed 4.0 record, as SETCLIENTID_CONFIRM would leave it.
    fn v40_confirmed() -> ClientKind {
        ClientKind::V40(V40 {
            confirmed: true,
            ..V40::new(verifier4::default())
        })
    }

    fn confirmed_v40_client(inner: &mut Inner, now: Instant) -> clientid4 {
        inner.install_client((Minor::V40, b"owner".to_vec()), verifier4::default(), v40_confirmed(), now)
    }

    /// A 4.1 client is confirmed by owning a session, so give it one.
    fn confirmed_v41_client(inner: &mut Inner, now: Instant) -> clientid4 {
        let kind = ClientKind::V41(V41 {
            create_session_seq: 1,
            sessions: Vec::new(),
        });
        let cid = inner.install_client((Minor::V41, b"owner41".to_vec()), verifier4::default(), kind, now);
        let sessionid = inner.fresh_sessionid();
        inner
            .clients
            .get_mut(&cid)
            .expect("just installed")
            .kind
            .v41_mut()
            .expect("v41")
            .sessions
            .push(Session {
                id: sessionid,
                slots: vec![Slot::default()].into_boxed_slice(),
                max_cached: 4096,
            });
        cid
    }

    /// OPEN(ReadOnly) then OPEN(ReadWrite) on one file must yield one state,
    /// upgraded in place, and one CLOSE must release it.
    #[test]
    fn repeat_open_upgrades_one_state() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);

        let first = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        assert!(first.confirm_required, "a new 4.0 open-owner needs OPEN_CONFIRM");

        assert!(matches!(
            inner.open_plan(cid, b"oo", OwnerSeqid::V40(2), 42, OpenMode::ReadWrite, now),
            Ok(OpenPlan::NeedHandle(OpenMode::ReadWrite))
        ));
        let second = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(2), 42, OpenMode::ReadWrite, handle(), now)
            .unwrap();

        assert_eq!(first.stateid.other, second.stateid.other, "one state per (owner, file)");
        assert_eq!(second.stateid.seqid, 2);
        assert_eq!(inner.opens().len(), 1);
        assert_eq!(inner.open_of(&second.stateid.other).mode, OpenMode::ReadWrite);

        // A ReadOnly OPEN is now satisfied without touching the VFS.
        assert!(matches!(
            inner.open_plan(cid, b"oo", OwnerSeqid::V40(3), 42, OpenMode::ReadOnly, now),
            Ok(OpenPlan::Done(_))
        ));

        inner.remove_open(cid, &second.stateid.other);
        assert!(inner.opens().is_empty() && inner.open_index_len() == 0);
        inner.assert_invariants();
    }

    /// A 4.1 CLOSE must release the state and hand its handle to the closer
    /// even when the dispatcher forwards the ignored wire seqid. Previously this
    /// was read as a replay of the OPEN, so the state — and the VFS handle —
    /// survived for the lifetime of the mount.
    #[test]
    fn v41_close_releases_the_handle_despite_a_stale_wire_seqid() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v41_client(&mut inner, now);
        let (fh, mut closed) = tracked_handle(11);

        // Both ops carry the same seqid, as a 4.1 client is entitled to.
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, fh, now)
            .unwrap();
        assert!(!opened.confirm_required, "4.1 has no OPEN_CONFIRM");
        assert!(closed.try_recv().is_err(), "handle must stay open while the state lives");

        let closed_sid = inner.close(cid, &opened.stateid, OwnerSeqid::V40(1), now).unwrap();
        assert_eq!(closed_sid.other, opened.stateid.other);
        assert_eq!(closed_sid.seqid, 2, "CLOSE bumps the stateid; it did not replay the OPEN");
        assert!(inner.opens().is_empty() && inner.open_index_len() == 0);
        assert_eq!(closed.try_recv().ok(), Some(11), "CLOSE must hand the handle to the closer");
        assert!(inner.retired.is_empty(), "4.1 needs no CLOSE tombstone");
        inner.assert_invariants();
    }

    /// Same root cause: with the reply recorded, a 4.1 OPEN of a second file
    /// under one open-owner used to replay the first file's stateid.
    #[test]
    fn v41_open_of_a_second_file_is_not_a_replay() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v41_client(&mut inner, now);

        let a = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        assert!(matches!(
            inner.open_plan(cid, b"oo", OwnerSeqid::V40(1), 43, OpenMode::ReadOnly, now),
            Ok(OpenPlan::NeedHandle(OpenMode::ReadOnly))
        ));
        let b = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 43, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        assert_ne!(a.stateid.other, b.stateid.other, "one state per file, not per open-owner");
        assert_eq!(inner.opens().len(), 2);
        inner.assert_invariants();
    }

    #[test]
    fn v41_keeps_no_open_owner_state() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v41_client(&mut inner, now);
        inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        // Structural, not merely empty: a 4.1 record has no open-owner table.
        assert!(inner.clients[&cid].open_owners().is_none());
        assert!(matches!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(1)), Ok(OwnerSeq::Fresh)));
        assert!(matches!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V41), Ok(OwnerSeq::Fresh)));
    }

    #[test]
    fn v41_cannot_open_confirm() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v41_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V41, 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        assert_eq!(inner.open_confirm(cid, &opened.stateid, 1, now), Err(nfsstat4::NFS4ERR_STALE_CLIENTID));
    }

    #[test]
    fn stale_stateid_seqid_is_rejected() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        let open = inner.open_of(&opened.stateid.other);
        assert_eq!(open.check_seqid(None), Ok(())); // 0 == current
        assert_eq!(open.check_seqid(NonZeroU32::new(1)), Ok(()));
        assert_eq!(open.check_seqid(NonZeroU32::new(2)), Err(nfsstat4::NFS4ERR_BAD_STATEID));

        inner.open_of_mut(&opened.stateid.other).bump(opened.stateid.other);
        assert_eq!(
            inner.open_of(&opened.stateid.other).check_seqid(NonZeroU32::new(1)),
            Err(nfsstat4::NFS4ERR_OLD_STATEID)
        );
    }

    #[test]
    fn owner_seqid_detects_retransmits() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(5), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        // Same seqid: replay the recorded reply, do not re-open.
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(5)), Ok(OwnerSeq::Replay(Ok(opened.stateid))));
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(6)), Ok(OwnerSeq::Fresh));
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(9)), Err(nfsstat4::NFS4ERR_BAD_SEQID));
    }

    /// The regression: an open-owner request that *failed* still consumed the
    /// client's seqid, so the next request must be accepted at last + 1. Booking
    /// only successes left the mirror one behind and every later OPEN/CLOSE drew
    /// NFS4ERR_BAD_SEQID for the life of the open-owner.
    #[test]
    fn failed_op_still_consumes_the_owner_seqid() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        // e.g. a phase-2 vfs::open failure, or a rejected OPEN_DOWNGRADE.
        assert_eq!(
            inner.record_owner_failure(cid, b"oo", OwnerSeqid::V40(2), nfsstat4::NFS4ERR_ACCESS),
            nfsstat4::NFS4ERR_ACCESS
        );

        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(3)), Ok(OwnerSeq::Fresh));
        // ...and the retransmit of the failure replays the same error.
        assert_eq!(
            inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(2)),
            Ok(OwnerSeq::Replay(Err(nfsstat4::NFS4ERR_ACCESS)))
        );
        inner.assert_invariants();
    }

    /// RFC 7530 §9.1.7's exception list: for these the client does *not*
    /// advance, so neither may the server.
    #[test]
    fn retained_errors_do_not_consume_the_owner_seqid() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        for status in [
            nfsstat4::NFS4ERR_BAD_STATEID,
            nfsstat4::NFS4ERR_STALE_STATEID,
            nfsstat4::NFS4ERR_BAD_SEQID,
            nfsstat4::NFS4ERR_NOFILEHANDLE,
        ] {
            inner.record_owner_failure(cid, b"oo", OwnerSeqid::V40(2), status);
            // Still expecting 2: nothing was consumed.
            assert_eq!(
                inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(2)),
                Ok(OwnerSeq::Fresh),
                "{status:?} must not advance the mirror"
            );
        }
        inner.assert_invariants();
    }

    /// The reported sequence: write, close, reopen, with a rejected
    /// OPEN_DOWNGRADE in the middle. Every seqid must be accepted in order.
    #[test]
    fn failed_op_does_not_desync_the_owner_seqid() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let (fh, mut closed) = tracked_handle(11);

        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, fh, now)
            .unwrap();
        // OPEN_DOWNGRADE: unsupported, rejected, seqid consumed regardless.
        assert_eq!(
            inner.note_owner_rejection(cid, b"oo", OwnerSeqid::V40(2), nfsstat4::NFS4ERR_NOTSUPP, now),
            nfsstat4::NFS4ERR_NOTSUPP
        );
        // The CLOSE that used to fail with BAD_SEQID.
        let sid = inner.close(cid, &opened.stateid, OwnerSeqid::V40(3), now).unwrap();
        assert_eq!(sid.other, opened.stateid.other);
        assert_eq!(closed.try_recv().ok(), Some(11));

        // And the reopen after it.
        assert!(matches!(
            inner.open_plan(cid, b"oo", OwnerSeqid::V40(4), 42, OpenMode::ReadWrite, now),
            Ok(OpenPlan::NeedHandle(OpenMode::ReadWrite))
        ));
        inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(4), 42, OpenMode::ReadWrite, handle(), now)
            .unwrap();
        inner.assert_invariants();
    }

    /// A rejected unsupported op must be idempotent under retransmit.
    #[test]
    fn rejected_owner_op_replays() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        let seqid = OwnerSeqid::V40(2);
        assert_eq!(
            inner.note_owner_rejection(cid, b"oo", seqid, nfsstat4::NFS4ERR_NOTSUPP, now),
            nfsstat4::NFS4ERR_NOTSUPP
        );
        assert_eq!(
            inner.note_owner_rejection(cid, b"oo", seqid, nfsstat4::NFS4ERR_NOTSUPP, now),
            nfsstat4::NFS4ERR_NOTSUPP,
            "retransmit replays, it does not advance twice"
        );
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(3)), Ok(OwnerSeq::Fresh));
    }

    /// A 4.0 CLOSE that is genuinely retransmitted must not close twice.
    #[test]
    fn v40_close_retransmit_replays() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let (fh, mut closed) = tracked_handle(11);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, fh, now)
            .unwrap();

        let first = inner.close(cid, &opened.stateid, OwnerSeqid::V40(2), now).unwrap();
        assert_eq!(closed.try_recv().ok(), Some(11));
        // The state is gone, so the retransmit is routed via the tombstone to
        // the open-owner record before it can reach `opens`.
        assert_eq!(inner.close(cid, &opened.stateid, OwnerSeqid::V40(2), now), Ok(first));
        assert!(closed.try_recv().is_err(), "must not close twice");
        assert_eq!(inner.close(cid, &opened.stateid, OwnerSeqid::V40(3), now), Err(nfsstat4::NFS4ERR_BAD_STATEID));
        inner.assert_invariants();
    }

    /// Only one tombstone per open-owner; the previous one is dropped with it.
    #[test]
    fn close_tombstone_is_one_per_open_owner() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);

        let a = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        inner.close(cid, &a.stateid, OwnerSeqid::V40(2), now).unwrap();
        let b = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(3), 43, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        inner.close(cid, &b.stateid, OwnerSeqid::V40(4), now).unwrap();

        assert_eq!(inner.retired.len(), 1);
        assert!(inner.retired.contains_key(&b.stateid.other));
        inner.assert_invariants();
    }

    /// An unknown stateid must not be booked against any open-owner.
    #[test]
    fn close_of_an_unknown_stateid_records_nothing() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();

        let bogus = stateid4 {
            seqid: 1,
            other: [0xab; NFS4_OTHER_SIZE],
        };
        assert_eq!(inner.close(cid, &bogus, OwnerSeqid::V40(2), now), Err(nfsstat4::NFS4ERR_BAD_STATEID));
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(2)), Ok(OwnerSeq::Fresh));
        inner.assert_invariants();
    }

    #[test]
    fn open_confirm_marks_the_owner_and_replays() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        assert!(opened.confirm_required);

        let confirmed = inner.open_confirm(cid, &opened.stateid, 2, now).unwrap();
        assert_eq!(confirmed.other, opened.stateid.other);
        assert_eq!(confirmed.seqid, 2);
        assert_eq!(inner.open_confirm(cid, &opened.stateid, 2, now), Ok(confirmed), "retransmit replays");

        // Confirmed once, so a later OPEN for this owner does not ask again.
        let again = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(3), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        assert!(!again.confirm_required);
        inner.assert_invariants();
    }

    #[test]
    fn expiry_purges_everything_the_client_owned() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let (fh, mut closed) = tracked_handle(11);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, fh, now)
            .unwrap();
        // Leave a tombstone behind too, so its cleanup is covered.
        let (other_fh, _) = tracked_handle(12);
        let second = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(2), 43, OpenMode::ReadOnly, other_fh, now)
            .unwrap();
        inner.close(cid, &second.stateid, OwnerSeqid::V40(3), now).unwrap();
        assert!(!inner.retired.is_empty());

        let later = now + LEASE + Duration::from_secs(1);
        assert_eq!(inner.client_mut(cid, later).err(), Some(nfsstat4::NFS4ERR_EXPIRED));
        assert!(inner.clients.is_empty() && inner.opens().is_empty() && inner.open_index_len() == 0);
        assert!(inner.retired.is_empty());
        assert_eq!(closed.try_recv().ok(), Some(11), "expiry must close the handle too");
        drop(opened);
        inner.assert_invariants();
    }

    #[test]
    fn versions_do_not_share_an_owner_namespace() {
        let now = Instant::now();
        let mut inner = inner();
        let a = inner.install_client((Minor::V40, b"same".to_vec()), verifier4::default(), v40_confirmed(), now);
        let b = inner.install_client(
            (Minor::V41, b"same".to_vec()),
            verifier4::default(),
            ClientKind::V41(V41 {
                create_session_seq: 1,
                sessions: Vec::new(),
            }),
            now,
        );
        assert_ne!(a, b);
        assert_eq!(inner.clients.len(), 2, "V40 and V41 owner ids are unrelated blobs");
        inner.assert_invariants();
    }

    /// A *fresh* seqid carrying a superseded stateid is still an error — but
    /// NFS4ERR_OLD_STATEID is absent from §9.1.7's retain list, so it consumes
    /// the seqid like any other failure and replays on retransmit.
    #[test]
    fn open_confirm_rejects_a_stale_stateid_on_a_fresh_seqid() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        inner.open_confirm(cid, &opened.stateid, 2, now).unwrap();

        // `opened.stateid` is now one behind the open's seqid.
        assert_eq!(inner.open_confirm(cid, &opened.stateid, 3, now), Err(nfsstat4::NFS4ERR_OLD_STATEID));
        assert_eq!(
            inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(3)),
            Ok(OwnerSeq::Replay(Err(nfsstat4::NFS4ERR_OLD_STATEID))),
            "the failure was booked, so its retransmit replays"
        );
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(4)), Ok(OwnerSeq::Fresh));
        inner.assert_invariants();
    }

    /// The regression: a SETCLIENTID retry from a client that had *not*
    /// rebooted minted a new clientid and purged the old record, closing every
    /// open file. Linux clients re-send SETCLIENTID on reconnect, so a mount
    /// would lose its handles mid-flight. State may only be discarded once a
    /// *changed* verifier has been confirmed.
    #[test]
    fn setclientid_retry_keeps_state_and_only_a_confirmed_reboot_drops_it() {
        let now = Instant::now();
        let mut inner = inner();
        let owner = (Minor::V40, b"host".to_vec());
        let v1 = verifier4::default();

        let (cid, confirm) = inner.setclientid(b"host", &v1, now);
        inner.setclientid_confirm(cid, &confirm, now).unwrap();

        let (fh, mut closed) = tracked_handle(11);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, fh, now)
            .unwrap();

        // Retry, same verifier: same clientid, state untouched.
        let (again, confirm2) = inner.setclientid(b"host", &v1, now);
        assert_eq!(again, cid, "an unrebooted client keeps its clientid");
        assert_eq!(inner.opens().len(), 1, "SETCLIENTID must not destroy open state");
        assert!(matches!(inner.resolve(cid, &opened.stateid, Instant::now()), Ok(Resolved::Open { .. })));
        assert!(closed.try_recv().is_err(), "the handle must not be closed");
        inner.setclientid_confirm(cid, &confirm2, now).unwrap();
        assert_eq!(inner.opens().len(), 1, "confirming a retry must not destroy it either");
        inner.assert_invariants();

        // Reboot: a different verifier gets a new, unconfirmed record, and the
        // old incarnation stays fully usable until the confirm lands.
        let mut v2 = verifier4::default();
        v2[0] ^= 1;
        let (rebooted, confirm3) = inner.setclientid(b"host", &v2, now);
        assert_ne!(rebooted, cid);
        assert_eq!(inner.by_owner(&owner), Some(cid), "confirmed record still current");
        assert_eq!(inner.unconfirmed.get(&owner), Some(&rebooted));
        assert!(matches!(inner.resolve(cid, &opened.stateid, Instant::now()), Ok(Resolved::Open { .. })));
        inner.assert_invariants();

        inner.setclientid_confirm(rebooted, &confirm3, now).unwrap();
        assert!(!inner.clients.contains_key(&cid), "the old incarnation is gone");
        assert!(inner.opens().is_empty() && inner.open_index_len() == 0);
        assert_eq!(closed.try_recv().ok(), Some(11), "the reboot closes the handle");
        assert_eq!(inner.by_owner(&owner), Some(rebooted));
        assert!(inner.unconfirmed.is_empty());
        inner.assert_invariants();
    }

    /// `by_owner` must name the *confirmed* incarnation while a reboot attempt
    /// is pending, whatever order `clients` happens to iterate in. This used to
    /// be a coin flip, which both flaked the test above and — via
    /// SETCLIENTID_CONFIRM's `old != cid` guard — sometimes left the previous
    /// incarnation and its open handles behind for good.
    #[test]
    fn by_owner_ignores_a_pending_setclientid() {
        let now = Instant::now();
        let owner = (Minor::V40, b"host".to_vec());

        // Repeat: one clientid pair per iteration, so any order-dependence shows.
        for _ in 0..64 {
            let mut inner = inner();
            let v1 = verifier4::default();
            let (cid, confirm) = inner.setclientid(b"host", &v1, now);
            inner.setclientid_confirm(cid, &confirm, now).unwrap();
            inner
                .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, handle(), now)
                .unwrap();

            let mut v2 = v1;
            v2[0] ^= 1;
            let (rebooted, confirm2) = inner.setclientid(b"host", &v2, now);
            assert_ne!(rebooted, cid);
            assert_eq!(inner.clients.len(), 2, "both incarnations coexist until the confirm");
            assert_eq!(inner.by_owner(&owner), Some(cid), "the pending record must not shadow the current one");
            inner.assert_invariants();

            inner.setclientid_confirm(rebooted, &confirm2, now).unwrap();
            assert_eq!(inner.by_owner(&owner), Some(rebooted));
            assert!(!inner.clients.contains_key(&cid), "the old incarnation must be retired");
            assert!(inner.opens().is_empty(), "and its state released");
            inner.assert_invariants();
        }
    }

    #[test]
    fn setclientid_confirm_rejects_a_wrong_verifier_without_touching_state() {
        let now = Instant::now();
        let mut inner = inner();
        let (cid, confirm) = inner.setclientid(b"host", &verifier4::default(), now);

        let mut wrong = confirm;
        wrong[0] ^= 1;
        assert_eq!(inner.setclientid_confirm(cid, &wrong, now), Err(nfsstat4::NFS4ERR_STALE_CLIENTID));
        assert!(!inner.clients[&cid].is_confirmed());

        inner.setclientid_confirm(cid, &confirm, now).unwrap();
        assert!(inner.clients[&cid].is_confirmed());
        // A superseded unconfirmed attempt must not linger in the index.
        let (next, _) = inner.setclientid(b"host", &verifier4::default(), now);
        assert_eq!(next, cid);
        assert!(inner.unconfirmed.is_empty());
        inner.assert_invariants();
    }

    /// RFC 7530 §9.5: naming a stateid renews the lease. A client doing nothing
    /// but READ/WRITE sends no RENEW, so without this it expires mid-transfer.
    #[test]
    fn resolve_renews_the_lease() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, handle(), now)
            .unwrap();

        // Two thirds of a lease in: still live, and this READ renews.
        let mid = now + LEASE * 2 / 3;
        assert!(matches!(inner.resolve(cid, &opened.stateid, mid), Ok(Resolved::Open { .. })));

        // Past the original deadline, but within a lease of the renewal.
        let later = mid + LEASE * 2 / 3;
        assert!(inner.client_mut(cid, later).is_ok(), "the READ must have renewed the lease");
        assert!(matches!(inner.resolve(cid, &opened.stateid, later), Ok(Resolved::Open { .. })));

        // A genuine lapse still expires, and takes the open state with it.
        let dead = later + LEASE + Duration::from_secs(1);
        assert_eq!(inner.resolve(cid, &opened.stateid, dead).err(), Some(nfsstat4::NFS4ERR_EXPIRED));
        assert!(inner.clients.is_empty() && inner.opens().is_empty());
        inner.assert_invariants();
    }

    /// A stateid belongs to the client it was issued to. Another client's
    /// READ/WRITE, CLOSE or OPEN_CONFIRM must not reach it, must not close its
    /// handle, and must not be booked against either open-owner.
    #[test]
    fn stateid_is_bound_to_its_client() {
        let now = Instant::now();
        let mut inner = inner();
        let victim = confirmed_v40_client(&mut inner, now);
        let attacker =
            inner.install_client((Minor::V40, b"attacker".to_vec()), verifier4::default(), v40_confirmed(), now);

        let (fh, mut closed) = tracked_handle(11);
        let opened = inner
            .open_commit(victim, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, fh, now)
            .unwrap();

        assert!(matches!(
            inner.resolve(attacker, &opened.stateid, Instant::now()),
            Err(nfsstat4::NFS4ERR_BAD_STATEID)
        ));
        assert_eq!(inner.open_confirm(attacker, &opened.stateid, 1, now), Err(nfsstat4::NFS4ERR_BAD_STATEID));
        assert_eq!(inner.close(attacker, &opened.stateid, OwnerSeqid::V40(1), now), Err(nfsstat4::NFS4ERR_BAD_STATEID));

        // Rejected before any open-owner is touched, and the victim is intact.
        assert_eq!(inner.check_owner_seqid(attacker, b"oo", OwnerSeqid::V40(1)), Ok(OwnerSeq::Fresh));
        assert!(closed.try_recv().is_err(), "the victim's handle must stay open");
        assert!(matches!(inner.resolve(victim, &opened.stateid, Instant::now()), Ok(Resolved::Open { .. })));

        // The CLOSE tombstone is bound to its client too.
        inner.close(victim, &opened.stateid, OwnerSeqid::V40(2), now).unwrap();
        assert_eq!(closed.try_recv().ok(), Some(11));
        assert_eq!(inner.close(attacker, &opened.stateid, OwnerSeqid::V40(1), now), Err(nfsstat4::NFS4ERR_BAD_STATEID));
        inner.assert_invariants();
    }

    /// NFS4ERR_BAD_SEQID is on RFC 7530 §9.1.7's retain list: the client does
    /// not advance its counter, so the server must not discard the open-owner
    /// either. Dropping it re-demanded OPEN_CONFIRM, turned every later seqid
    /// into a `Fresh` (killing replay detection), and orphaned the CLOSE
    /// tombstone — which `assert_invariants` catches.
    #[test]
    fn bad_seqid_preserves_the_open_owner() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);

        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        // OPEN_CONFIRM bumps the open's seqid, so CLOSE must carry what it
        // returned, not the stateid OPEN handed out.
        let confirmed = inner.open_confirm(cid, &opened.stateid, 2, now).unwrap();
        let closed = inner.close(cid, &confirmed, OwnerSeqid::V40(3), now).unwrap();
        assert!(inner.retired.contains_key(&closed.other));

        // A gap in the client's counter.
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(9)), Err(nfsstat4::NFS4ERR_BAD_SEQID));

        // Nothing was forgotten...
        assert_eq!(
            inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(3)),
            Ok(OwnerSeq::Replay(Ok(closed))),
            "the replay record must survive"
        );
        assert!(!inner.confirm_required(cid, b"oo"), "OPEN_CONFIRM must not be demanded again");
        assert!(inner.retired.contains_key(&closed.other), "the tombstone must survive");

        // ...and the legitimate next request is still accepted.
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(4)), Ok(OwnerSeq::Fresh));
        inner.assert_invariants();
    }

    /// State belongs to its client rather than to a server-wide table: removing
    /// one client must retract exactly its own locator entries — opens,
    /// tombstones and sessions — and leave every other client's untouched. The
    /// previous `retain`-based sweep only worked because each record carried a
    /// redundant clientid, and forgetting one table leaked silently.
    #[test]
    fn client_owns_its_state() {
        let now = Instant::now();
        let mut inner = inner();
        let a = confirmed_v40_client(&mut inner, now);
        let b = inner.install_client((Minor::V40, b"other".to_vec()), verifier4::default(), v40_confirmed(), now);
        let c = confirmed_v41_client(&mut inner, now);

        // `a` gets one live open and one tombstone.
        let (fh, mut closed) = tracked_handle(11);
        let live = inner
            .open_commit(a, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, fh, now)
            .unwrap();
        let gone = inner
            .open_commit(a, b"oo2", OwnerSeqid::V40(1), 43, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        inner.close(a, &gone.stateid, OwnerSeqid::V40(2), now).unwrap();

        // `b` opens the same file under the same open-owner *name*: the
        // namespace is per-client, so this is a distinct state.
        let theirs = inner
            .open_commit(b, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadOnly, handle(), now)
            .unwrap();
        assert_ne!(live.stateid.other, theirs.stateid.other);

        assert_eq!(inner.clients[&a].opens.len(), 1);
        assert_eq!(inner.clients[&a].open_index.len(), 1);
        assert_eq!(inner.opens().len(), 2, "one locator entry per live open");
        assert_eq!(inner.sessions().len(), 1);
        inner.assert_invariants();

        inner.remove_client(a);

        assert!(!inner.retired.contains_key(&gone.stateid.other), "tombstone not retracted");
        assert_eq!(closed.try_recv().ok(), Some(11), "removal must close the handle");

        // Everything belonging to the other clients survived.
        assert_eq!(inner.open_index_len(), 1);
        assert_eq!(inner.sessions().len(), 1, "the 4.1 client keeps its session");
        inner.assert_invariants();

        inner.remove_client(c);
        assert!(inner.sessions().is_empty(), "session locator not retracted");
        inner.assert_invariants();
    }

    /// macOS TextEdit's save: OPEN(BOTH), OPEN_CONFIRM, WRITE, OPEN_DOWNGRADE
    /// to read-only, CLOSE. OPEN_DOWNGRADE names the open-owner and consumes
    /// its seqid whatever the server does with it (RFC 7530 §9.1.7), so
    /// answering NFS4ERR_NOTSUPP without booking it left the mirror one behind
    /// and drew NFS4ERR_BAD_SEQID on the CLOSE — and on every OPEN/CLOSE from
    /// that open-owner thereafter, for the life of the mount.
    #[test]
    fn open_downgrade_keeps_the_owner_seqid_level() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let (fh, mut closed) = tracked_handle(11);

        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, fh, now)
            .unwrap();
        let confirmed = inner.open_confirm(cid, &opened.stateid, 2, now).unwrap();

        // The downgrade: next seqid, carrying the stateid OPEN_CONFIRM returned.
        let down = inner
            .open_downgrade(cid, &confirmed, OwnerSeqid::V40(3), now)
            .expect("OPEN_DOWNGRADE must be answered, not rejected");
        assert_eq!(down.other, confirmed.other, "same open state");
        assert_eq!(down.seqid, confirmed.seqid + 1, "a downgrade advances the stateid");
        assert!(closed.try_recv().is_err(), "the state is still open");

        // The state stays usable through the surviving handle.
        assert!(matches!(inner.resolve(cid, &down, now), Ok(Resolved::Open { .. })));

        // The CLOSE that used to fail with BAD_SEQID.
        let sid = inner
            .close(cid, &down, OwnerSeqid::V40(4), now)
            .expect("the downgrade must have consumed seqid 3");
        assert_eq!(sid.other, confirmed.other);
        assert_eq!(closed.try_recv().ok(), Some(11), "CLOSE releases the handle");
        assert!(inner.opens().is_empty() && inner.open_index_len() == 0);
        inner.assert_invariants();
    }

    /// A retransmitted OPEN_DOWNGRADE replays; it must not advance twice, and
    /// must not leave a gap that the following CLOSE falls into.
    #[test]
    fn open_downgrade_retransmit_replays() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, handle(), now)
            .unwrap();
        let confirmed = inner.open_confirm(cid, &opened.stateid, 2, now).unwrap();

        let down = inner.open_downgrade(cid, &confirmed, OwnerSeqid::V40(3), now).unwrap();
        // Same seqid *and* the now-superseded stateid, as a retransmit carries.
        assert_eq!(
            inner.open_downgrade(cid, &confirmed, OwnerSeqid::V40(3), now),
            Ok(down),
            "retransmit replays the recorded reply"
        );
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(4)), Ok(OwnerSeq::Fresh));
        inner.assert_invariants();
    }

    /// LOCK is unsupported, but `open_to_lock_owner4` still consumes the
    /// open-owner's seqid, so the rejection has to be booked like any reply.
    #[test]
    fn rejected_lock_books_the_open_owner_seqid() {
        let now = Instant::now();
        let mut inner = inner();
        let cid = confirmed_v40_client(&mut inner, now);
        let opened = inner
            .open_commit(cid, b"oo", OwnerSeqid::V40(1), 42, OpenMode::ReadWrite, handle(), now)
            .unwrap();

        assert_eq!(
            inner.note_stateid_rejection(cid, &opened.stateid, OwnerSeqid::V40(2), nfsstat4::NFS4ERR_NOTSUPP, now),
            nfsstat4::NFS4ERR_NOTSUPP
        );
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(3)), Ok(OwnerSeq::Fresh));
        // An unknown stateid is BAD_STATEID — retained, so nothing is booked.
        let bogus = stateid4 {
            seqid: 1,
            other: [0xab; NFS4_OTHER_SIZE],
        };
        assert_eq!(
            inner.note_stateid_rejection(cid, &bogus, OwnerSeqid::V40(3), nfsstat4::NFS4ERR_NOTSUPP, now),
            nfsstat4::NFS4ERR_BAD_STATEID
        );
        assert_eq!(inner.check_owner_seqid(cid, b"oo", OwnerSeqid::V40(3)), Ok(OwnerSeq::Fresh));
        inner.assert_invariants();
    }
}
