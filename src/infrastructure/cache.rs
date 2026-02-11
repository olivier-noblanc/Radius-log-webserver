use crate::core::models::RadiusRequest;
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct LogCache {
    items: DashMap<usize, RadiusRequest>,
    next_id: AtomicUsize,
}

impl LogCache {
    pub fn new() -> Self {
        Self {
            items: DashMap::new(),
            next_id: AtomicUsize::new(0),
        }
    }

    pub fn read(&self) -> Vec<RadiusRequest> {
        let mut v: Vec<_> = self.items.iter().map(|entry| entry.value().clone()).collect();
        // DashMap iter is unordered. If we need order, we should sort by timestamp or use the keys.
        v.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        v
    }

    pub fn extend(&self, new_items: Vec<RadiusRequest>) {
        for item in new_items {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            self.items.insert(id, item);
        }
    }

    pub fn clear(&self) {
        self.items.clear();
        self.next_id.store(0, Ordering::SeqCst);
    }

    pub fn set(&self, new_items: Vec<RadiusRequest>) {
        self.clear();
        self.extend(new_items);
    }

    pub fn get_latest(&self, count: usize) -> Vec<RadiusRequest> {
        let total = self.next_id.load(Ordering::SeqCst);
        let start = total.saturating_sub(count);
        
        let mut result = Vec::with_capacity(count);
        for i in start..total {
            if let Some(item) = self.items.get(&i) {
                result.push(item.value().clone());
            }
        }
        result
    }
}

impl Default for LogCache {
    fn default() -> Self {
        Self::new()
    }
}
