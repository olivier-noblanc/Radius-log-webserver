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
        v.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); // Tri décroissant pour l'affichage
        v
    }

    pub fn extend(&self, new_items: Vec<RadiusRequest>) {
        for mut item in new_items {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            // FIX: On assigne l'ID ici
            item.id = Some(id);
            self.items.insert(id, item);
        }
    }

    // FIX: Méthode pour récupérer un log par son ID unique
    pub fn get_by_id(&self, id: usize) -> Option<RadiusRequest> {
        self.items.get(&id).map(|r| r.value().clone())
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
        let mut v = self.read();
        v.truncate(count);
        v
    }
}

impl Default for LogCache {
    fn default() -> Self {
        Self::new()
    }
}

use std::sync::RwLock;
use std::time::{Duration, Instant};
use crate::api::handlers::stats::Stats;

pub struct StatsCache {
    data: RwLock<Option<(Stats, Instant)>>,
    ttl: Duration,
}

impl StatsCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            data: RwLock::new(None),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }
    
    pub fn get_or_compute<F>(&self, compute_fn: F) -> Stats
    where
        F: FnOnce() -> Stats,
    {
        // Try read first (fast path)
        {
            let read = self.data.read().unwrap();
            if let Some((stats, timestamp)) = read.as_ref() {
                if timestamp.elapsed() < self.ttl {
                    return stats.clone();
                }
            }
        }
        
        // Compute new stats (slow path)
        let new_stats = compute_fn();
        
        // Write to cache
        {
            let mut write = self.data.write().unwrap();
            *write = Some((new_stats.clone(), Instant::now()));
        }
        
        new_stats
    }
    
    pub fn invalidate(&self) {
        let mut write = self.data.write().unwrap();
        *write = None;
    }
}

impl Default for StatsCache {
    fn default() -> Self {
        Self::new(30) // 30 secondes par défaut
    }
}