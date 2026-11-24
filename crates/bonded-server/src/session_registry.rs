use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHandle {
    pub session_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub client_key: String,
    pub session_id: u64,
}

#[derive(Debug, Default, Clone)]
pub struct SessionRegistry {
    inner: Arc<RwLock<SessionRegistryInner>>,
}

#[derive(Debug, Default)]
struct SessionRegistryInner {
    next_session_id: u64,
    sessions_by_client: HashMap<String, SessionHandle>,
    /// Last-seen transport source IP per client key (4.107): the
    /// address the server most recently observed that device
    /// connecting from. A device with several live transports
    /// (Wi-Fi + cellular) has one entry — the most recent — so
    /// introduction minting resolves the network name from the
    /// last-seen transport, not from a per-leg address (the pong
    /// path carries the exact per-leg name instead). Updated on
    /// every transport bind, cleared with the session on
    /// unregister.
    source_ip_by_client: HashMap<String, std::net::IpAddr>,
}

impl SessionRegistry {
    pub fn register_client(&self, client_key: String) -> SessionHandle {
        let mut guard = self
            .inner
            .write()
            .expect("session registry write lock should not be poisoned");

        if let Some(existing) = guard.sessions_by_client.get(&client_key).copied() {
            return existing;
        }

        let session_id = guard.next_session_id;
        guard.next_session_id = guard.next_session_id.wrapping_add(1);
        let handle = SessionHandle { session_id };
        guard.sessions_by_client.insert(client_key, handle);
        handle
    }

    pub fn unregister_client(&self, client_key: &str) {
        let mut guard = self
            .inner
            .write()
            .expect("session registry write lock should not be poisoned");
        guard.sessions_by_client.remove(client_key);
        guard.source_ip_by_client.remove(client_key);
    }

    /// Record the transport source address a client key was most
    /// recently observed connecting from (4.107). Called on every
    /// transport bind — WSS, QUIC, NaiveTCP, and WireGuard — next
    /// to `register_client`, so the last bind wins. The address is
    /// what introduction minting resolves the peer's network name
    /// from.
    pub fn note_source_ip(&self, client_key: &str, peer: std::net::SocketAddr) {
        let mut guard = self
            .inner
            .write()
            .expect("session registry write lock should not be poisoned");
        guard
            .source_ip_by_client
            .insert(client_key.to_owned(), peer.ip());
    }

    /// The last-seen source IP for a live session registered under
    /// this client key, if any (4.107). `None` means the device has
    /// no live session (or no transport has been noted yet) and an
    /// introduction for it carries no network name — never an
    /// invented one.
    pub fn source_ip_for(&self, client_key: &str) -> Option<std::net::IpAddr> {
        self.inner
            .read()
            .expect("session registry read lock should not be poisoned")
            .source_ip_by_client
            .get(client_key)
            .copied()
    }

    pub fn contains_client(&self, client_key: &str) -> bool {
        self.inner
            .read()
            .expect("session registry read lock should not be poisoned")
            .sessions_by_client
            .contains_key(client_key)
    }

    /// The session id a live session registered under this client key,
    /// if any (4.56: the dial-back push addresses the provider's
    /// session by its registered id). `None` means the device has no
    /// live session and a push to it must be dropped, not queued.
    pub fn session_id_for(&self, client_key: &str) -> Option<u64> {
        self.inner
            .read()
            .expect("session registry read lock should not be poisoned")
            .sessions_by_client
            .get(client_key)
            .map(|handle| handle.session_id)
    }

    pub fn active_sessions(&self) -> usize {
        self.inner
            .read()
            .expect("session registry read lock should not be poisoned")
            .sessions_by_client
            .len()
    }

    pub fn snapshot(&self) -> Vec<SessionSnapshot> {
        let guard = self
            .inner
            .read()
            .expect("session registry read lock should not be poisoned");

        guard
            .sessions_by_client
            .iter()
            .map(|(client_key, handle)| SessionSnapshot {
                client_key: client_key.clone(),
                session_id: handle.session_id,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::SessionRegistry;

    #[test]
    fn registering_clients_tracks_unique_sessions() {
        let registry = SessionRegistry::default();
        let first = registry.register_client("pub-a".to_owned());
        let second = registry.register_client("pub-b".to_owned());

        assert_ne!(first.session_id, second.session_id);
        assert_eq!(registry.active_sessions(), 2);
    }

    #[test]
    fn registering_same_client_reuses_session_handle() {
        let registry = SessionRegistry::default();
        let first = registry.register_client("pub-a".to_owned());
        let second = registry.register_client("pub-a".to_owned());

        assert_eq!(first.session_id, second.session_id);
        assert_eq!(registry.active_sessions(), 1);
    }

    #[test]
    fn unregister_removes_client_session() {
        let registry = SessionRegistry::default();
        let _ = registry.register_client("pub-a".to_owned());
        registry.unregister_client("pub-a");
        assert_eq!(registry.active_sessions(), 0);
    }

    #[test]
    fn source_ip_tracks_last_seen_transport_and_clears_on_unregister() {
        // 4.107: the registry remembers the most recent transport
        // source IP per client; a re-bind overwrites it and
        // unregister clears it, so minting never resolves a name
        // from a dead session's address.
        let registry = SessionRegistry::default();
        assert_eq!(registry.source_ip_for("pub-a"), None);
        let _ = registry.register_client("pub-a".to_owned());
        registry.note_source_ip("pub-a", "75.164.76.151:54321".parse().unwrap());
        assert_eq!(
            registry.source_ip_for("pub-a"),
            Some("75.164.76.151".parse().unwrap())
        );
        registry.note_source_ip("pub-a", "1.1.1.1:443".parse().unwrap());
        assert_eq!(
            registry.source_ip_for("pub-a"),
            Some("1.1.1.1".parse().unwrap())
        );
        registry.unregister_client("pub-a");
        assert_eq!(registry.source_ip_for("pub-a"), None);
    }

    #[test]
    fn contains_client_tracks_registration_state() {
        let registry = SessionRegistry::default();
        assert!(!registry.contains_client("pub-a"));

        let _ = registry.register_client("pub-a".to_owned());
        assert!(registry.contains_client("pub-a"));

        registry.unregister_client("pub-a");
        assert!(!registry.contains_client("pub-a"));
    }
}
