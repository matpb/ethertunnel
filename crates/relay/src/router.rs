//! The routing table: which session currently serves each hostname / TCP port.
//!
//! A plain `RwLock<HashMap>` rather than a concurrent map, because a claim must
//! atomically (a) read-compare-replace several hostname/port entries and (b)
//! update the reverse index — multi-key atomicity that a sharded map makes
//! awkward. Critical sections are tiny: clone a cheap handle out, never await
//! under the lock.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::Duration;

use ethertunnel_proto::frames::{ControlFrame, Resource, StreamHeader};
use tokio::sync::{mpsc, oneshot};

use crate::session::{DataStream, OpenError, SessionCmd};

/// A cheap, cloneable handle to a live daemon session. Lives in the routing
/// table; the data path clones it out under a read lock.
#[derive(Clone)]
pub struct SessionHandle {
    pub session_id: u64,
    pub user_id: i64,
    /// Outgoing control frames are funneled through this channel to the
    /// session's single writer task (so writes never race).
    ctrl_tx: mpsc::Sender<ControlFrame>,
    /// Commands to the session actor (e.g. open a data stream to the daemon).
    cmd_tx: mpsc::Sender<SessionCmd>,
}

impl SessionHandle {
    pub fn new(
        session_id: u64,
        user_id: i64,
        ctrl_tx: mpsc::Sender<ControlFrame>,
        cmd_tx: mpsc::Sender<SessionCmd>,
    ) -> Self {
        Self {
            session_id,
            user_id,
            ctrl_tx,
            cmd_tx,
        }
    }

    /// Enqueue a control frame to this session. Best-effort: a full or closed
    /// channel drops the frame (the session is already overloaded or gone).
    pub fn send_ctrl(&self, frame: ControlFrame) {
        let _ = self.ctrl_tx.try_send(frame);
    }

    /// Open a fresh multiplexed stream to the daemon, with `header` written as
    /// the preamble. The returned stream carries opaque bytes thereafter.
    pub async fn open_stream(&self, header: StreamHeader) -> Result<DataStream, OpenError> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCmd::OpenStream { header, reply })
            .await
            .map_err(|_| OpenError::SessionClosed)?;
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(OpenError::SessionClosed),
            Err(_) => Err(OpenError::Timeout),
        }
    }
}

#[derive(Default)]
struct ClaimSet {
    hosts: HashSet<String>,
    ports: HashSet<u16>,
}

#[derive(Default)]
struct RouterInner {
    http: HashMap<String, SessionHandle>, // FQDN (lowercase) -> session
    tcp: HashMap<u16, SessionHandle>,
    by_session: HashMap<u64, ClaimSet>, // reverse index for teardown
}

/// The relay's hostname/port routing table.
#[derive(Default)]
pub struct Router {
    inner: RwLock<RouterInner>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a hostname to its serving session, if any.
    pub fn lookup_http(&self, host: &str) -> Option<SessionHandle> {
        self.inner.read().unwrap().http.get(host).cloned()
    }

    /// Resolve a public TCP port to its serving session, if any.
    pub fn lookup_tcp(&self, port: u16) -> Option<SessionHandle> {
        self.inner.read().unwrap().tcp.get(&port).cloned()
    }

    /// Point the given hostnames and ports at `session`, taking them over from
    /// any session that currently holds them ("newest wins"). Returns the
    /// superseded `(handle, resource)` pairs so the caller can notify the old
    /// sessions *outside* the lock. Idempotent: re-claiming what this session
    /// already holds is a no-op.
    pub fn claim(
        &self,
        session: &SessionHandle,
        hosts: &[String],
        ports: &[u16],
    ) -> Vec<(SessionHandle, Resource)> {
        let mut inner = self.inner.write().unwrap();
        let mut superseded = Vec::new();

        for host in hosts {
            if let Some(prev) = inner.http.insert(host.clone(), session.clone()) {
                if prev.session_id != session.session_id {
                    // remove from the previous session's reverse index
                    if let Some(set) = inner.by_session.get_mut(&prev.session_id) {
                        set.hosts.remove(host);
                    }
                    superseded.push((prev, Resource::Host(host.clone())));
                }
            }
            inner
                .by_session
                .entry(session.session_id)
                .or_default()
                .hosts
                .insert(host.clone());
        }

        for &port in ports {
            if let Some(prev) = inner.tcp.insert(port, session.clone()) {
                if prev.session_id != session.session_id {
                    if let Some(set) = inner.by_session.get_mut(&prev.session_id) {
                        set.ports.remove(&port);
                    }
                    superseded.push((prev, Resource::Port(port)));
                }
            }
            inner
                .by_session
                .entry(session.session_id)
                .or_default()
                .ports
                .insert(port);
        }

        superseded
    }

    /// Remove every route still pointing at this session. The `session_id`
    /// guard ensures a session that was superseded then disconnects cannot
    /// evict the *new* owner's entries.
    pub fn remove_session(&self, session_id: u64) {
        let mut inner = self.inner.write().unwrap();
        let Some(set) = inner.by_session.remove(&session_id) else {
            return;
        };
        for host in set.hosts {
            if inner
                .http
                .get(&host)
                .is_some_and(|h| h.session_id == session_id)
            {
                inner.http.remove(&host);
            }
        }
        for port in set.ports {
            if inner
                .tcp
                .get(&port)
                .is_some_and(|h| h.session_id == session_id)
            {
                inner.tcp.remove(&port);
            }
        }
    }

    /// Number of routed hostnames (for diagnostics/tests).
    pub fn hostname_count(&self) -> usize {
        self.inner.read().unwrap().http.len()
    }

    /// Count the distinct active tunnels (hostnames + TCP ports) `user_id` would
    /// hold *after* additionally claiming `new_hosts`/`new_ports`. Re-claims of
    /// resources the user already holds do not double-count (set union). Used to
    /// enforce a per-customer `max_tunnels` cap at claim time.
    ///
    /// There is an inherent ±1 race here (the count is read before the claim is
    /// applied under a separate lock); it is accepted as benign — it can only
    /// ever let through one extra tunnel against a quota, never wrongly deny an
    /// owner their resources.
    pub fn projected_tunnel_count(
        &self,
        user_id: i64,
        new_hosts: &[String],
        new_ports: &[u16],
    ) -> usize {
        let inner = self.inner.read().unwrap();
        let mut hosts: HashSet<&str> = inner
            .http
            .iter()
            .filter(|(_, h)| h.user_id == user_id)
            .map(|(k, _)| k.as_str())
            .collect();
        for h in new_hosts {
            hosts.insert(h.as_str());
        }
        let mut ports: HashSet<u16> = inner
            .tcp
            .iter()
            .filter(|(_, h)| h.user_id == user_id)
            .map(|(p, _)| *p)
            .collect();
        for p in new_ports {
            ports.insert(*p);
        }
        hosts.len() + ports.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(session_id: u64, user_id: i64) -> (SessionHandle, mpsc::Receiver<ControlFrame>) {
        let (tx, rx) = mpsc::channel(16);
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        (SessionHandle::new(session_id, user_id, tx, cmd_tx), rx)
    }

    #[test]
    fn claim_and_lookup() {
        let r = Router::new();
        let (h, _rx) = handle(1, 100);
        let superseded = r.claim(&h, &["a.example.com".into()], &[20000]);
        assert!(superseded.is_empty());
        assert_eq!(r.lookup_http("a.example.com").unwrap().session_id, 1);
        assert_eq!(r.lookup_tcp(20000).unwrap().session_id, 1);
        assert!(r.lookup_http("b.example.com").is_none());
    }

    #[test]
    fn newest_session_supersedes_and_old_disconnect_is_safe() {
        let r = Router::new();
        let (h1, _rx1) = handle(1, 100);
        let (h2, _rx2) = handle(2, 100); // same user, newer session

        r.claim(&h1, &["a.example.com".into()], &[]);
        let superseded = r.claim(&h2, &["a.example.com".into()], &[]);

        // h1 was superseded for that host.
        assert_eq!(superseded.len(), 1);
        assert_eq!(superseded[0].0.session_id, 1);
        assert_eq!(superseded[0].1, Resource::Host("a.example.com".into()));
        // Route now points at the newer session.
        assert_eq!(r.lookup_http("a.example.com").unwrap().session_id, 2);

        // The old session disconnecting must NOT evict the new owner.
        r.remove_session(1);
        assert_eq!(
            r.lookup_http("a.example.com").unwrap().session_id,
            2,
            "old session teardown wrongly evicted the new claim"
        );

        // The new session disconnecting clears it.
        r.remove_session(2);
        assert!(r.lookup_http("a.example.com").is_none());
    }

    #[test]
    fn reclaim_same_session_is_noop() {
        let r = Router::new();
        let (h, _rx) = handle(1, 100);
        assert!(r.claim(&h, &["a.example.com".into()], &[]).is_empty());
        assert!(
            r.claim(&h, &["a.example.com".into()], &[]).is_empty(),
            "re-claiming an owned hostname should not supersede self"
        );
        assert_eq!(r.hostname_count(), 1);
    }
}
