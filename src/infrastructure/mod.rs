pub mod cache;
pub mod file_watcher;
pub mod security_audit;
pub mod win32;

// Trait définit ici pour être partagé entre FileWatcher et WebSocket
pub trait MessageBroadcaster: Send + Sync {
    fn broadcast(&self, msg: String);
}
