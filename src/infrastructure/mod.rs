pub mod win32;
pub mod file_watcher;
pub mod cache;

// Trait définit ici pour être partagé entre FileWatcher et WebSocket
pub trait MessageBroadcaster: Send + Sync {
    fn broadcast(&self, msg: String);
}