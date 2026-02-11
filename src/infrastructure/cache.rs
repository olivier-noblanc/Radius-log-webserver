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