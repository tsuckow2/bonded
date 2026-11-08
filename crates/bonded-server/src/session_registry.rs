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
    fn contains_client_tracks_registration_state() {
        let registry = SessionRegistry::default();
        assert!(!registry.contains_client("pub-a"));

        let _ = registry.register_client("pub-a".to_owned());
        assert!(registry.contains_client("pub-a"));

        registry.unregister_client("pub-a");
        assert!(!registry.contains_client("pub-a"));
    }
}
