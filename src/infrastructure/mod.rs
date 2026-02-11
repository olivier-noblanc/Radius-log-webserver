pub mod win32;
pub mod file_watcher;
pub mod cache;

pub trait MessageBroadcaster: Send + Sync {
    fn broadcast(&self, msg: String);
}
