use crate::core::parser::parse_xml_bytes;
use crate::infrastructure::cache::LogCache;
use crate::core::models::RadiusRequest;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use quick_xml::reader::Reader;
use std::fs::{self, File};
use std::io::{BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use dashmap::DashMap;
use crate::infrastructure::MessageBroadcaster;

pub struct FileWatcher {
    broadcaster: Arc<dyn MessageBroadcaster>,
    file_sizes: Arc<DashMap<String, u64>>,
    cache: Arc<LogCache>,
    stats_cache: Arc<crate::infrastructure::cache::StatsCache>,
}

impl FileWatcher {
    pub fn new(
        broadcaster: Arc<dyn MessageBroadcaster>,
        cache: Arc<LogCache>,
        stats_cache: Arc<crate::infrastructure::cache::StatsCache>,
    ) -> Self {
        Self {
            broadcaster,
            file_sizes: Arc::new(DashMap::new()),
            cache,
            stats_cache,
        }
    }

    pub fn start(&self, path_str: String) {
        let path = PathBuf::from(path_str);
        
        // Initial scan
        if let Ok(entries) = fs::read_dir(&path) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    self.file_sizes.insert(entry.path().to_string_lossy().to_string(), meta.len());
                }
            }
        }

        let broadcaster = self.broadcaster.clone();
        let file_sizes = self.file_sizes.clone();
        let cache = self.cache.clone();
        let stats_cache = self.stats_cache.clone();

        thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();

            if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
                eprintln!("Watcher error: {:?}", e);
                return;
            }

            for res in rx {
                match res {
                    Ok(event) => {
                        if event.kind.is_modify() {
                            for p in event.paths {
                                if p.extension().is_some_and(|e| e == "log") {
                                    process_file_change(&p, &broadcaster, &file_sizes, &cache, &stats_cache);
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("Watch error: {:?}", e),
                }
            }
        });
    }
}

fn process_file_change(
    path: &Path,
    broadcaster: &Arc<dyn MessageBroadcaster>,
    file_sizes: &Arc<DashMap<String, u64>>,
    cache: &Arc<LogCache>,
    stats_cache: &Arc<crate::infrastructure::cache::StatsCache>,
) {
    let path_str = path.to_string_lossy().to_string();
    let old_size = file_sizes.get(&path_str).map(|r| *r.value()).unwrap_or(0);

    if let Ok(meta) = fs::metadata(path) {
        let new_size = meta.len();
        if new_size > old_size {
            if let Ok(mut file) = File::open(path) {
                if file.seek(SeekFrom::Start(old_size)).is_ok() {
                    let mut reader = Reader::from_reader(BufReader::new(file));
                    let new_reqs = parse_xml_bytes(&mut reader, None, 100);
                    if !new_reqs.is_empty() {
                        // Update cache
                        cache.extend(new_reqs.clone());

                        // Invalidate stats cache
                        stats_cache.invalidate();

                        // Broadcast fragment
                        let html_fragment: String = new_reqs
                            .iter()
                            .map(render_row)
                            .collect();

                        broadcaster.broadcast(html_fragment);
                        file_sizes.insert(path_str, new_size);
                    }
                }
            }
        } else if new_size < old_size {
            // Truncated
            cache.clear();
            file_sizes.insert(path_str, new_size);
            // In a real app we might re-parse everything here if it's the latest file
        }
    }
}

fn render_row(r: &RadiusRequest) -> String {
    let status_val = r.status.as_deref().unwrap_or("");
    format!(
        "<tr class='row-flash' style='cursor: pointer;' onclick='showDetails({})'><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td data-status='{}'>{}</td><td>{}</td></tr>",
        serde_json::to_string(r).unwrap_or_default().replace('\'', "\\'"),
        r.timestamp, r.req_type, r.server, r.ap_ip, r.ap_name, r.mac, r.user, status_val, r.resp_type, r.reason
    )
}
