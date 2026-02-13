use crate::core::models::{RadiusEvent, RadiusRequest};
use crate::core::reason_map::{map_packet_type, map_reason};
use aho_corasick::AhoCorasick;
use memmap2::Mmap;
use quick_xml::events::Event as XmlEvent;
use quick_xml::reader::Reader;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::Cursor;

pub fn parse_log_with_mmap(mmap: &Mmap, search: Option<&str>, limit: usize) -> Vec<RadiusRequest> {
    let mut reader = Reader::from_reader(Cursor::new(&mmap[..]));
    parse_xml_bytes(&mut reader, search, limit)
}

pub fn parse_xml_bytes<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    search: Option<&str>,
    limit: usize,
) -> Vec<RadiusRequest> {
    let mut buf = Vec::new();
    let mut event_blobs = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) if e.name().as_ref() == b"Event" => {
                let mut blob = Vec::new();
                blob.push(b'<');
                blob.extend_from_slice(&buf);
                blob.push(b'>');

                let mut depth = 1;
                while depth > 0 {
                    let mut inner_buf = Vec::new();
                    match reader.read_event_into(&mut inner_buf) {
                        Ok(XmlEvent::Start(_)) => {
                            depth += 1;
                            blob.push(b'<');
                            blob.extend_from_slice(&inner_buf);
                            blob.push(b'>');
                        }
                        Ok(XmlEvent::End(ref ee)) => {
                            depth -= 1;
                            blob.extend_from_slice(b"</");
                            blob.extend_from_slice(ee.name().as_ref());
                            blob.push(b'>');
                        }
                        Ok(XmlEvent::Empty(ref _ee)) => {
                            // Empty tags don't change depth but need to be appended correctly
                            blob.push(b'<');
                            blob.extend_from_slice(&inner_buf);
                            blob.extend_from_slice(b"/>");
                        }
                        Ok(XmlEvent::Text(_)) => {
                            blob.extend_from_slice(&inner_buf);
                        }
                        Ok(XmlEvent::CData(_)) => {
                            blob.extend_from_slice(b"<![CDATA[");
                            blob.extend_from_slice(&inner_buf);
                            blob.extend_from_slice(b"]]>");
                        }
                        Ok(XmlEvent::Comment(_)) => {
                            blob.extend_from_slice(b"<!--");
                            blob.extend_from_slice(&inner_buf);
                            blob.extend_from_slice(b"-->");
                        }
                        Ok(XmlEvent::Eof) => {
                            break;
                        }
                        _ => {
                            blob.extend_from_slice(&inner_buf);
                        }
                    }
                }
                event_blobs.push(blob);
            }
            Ok(XmlEvent::Empty(ref e)) if e.name().as_ref() == b"Event" => {
                let mut blob = Vec::new();
                blob.push(b'<');
                blob.extend_from_slice(&buf);
                blob.extend_from_slice(b"/>");
                event_blobs.push(blob);
            }
            Ok(XmlEvent::Eof) => break,
            Err(e) => {
                tracing::error!("XML reading error: {}", e);
                break;
            }
            _ => (),
        }
    }

    if event_blobs.is_empty() {
        tracing::warn!("No <Event> tags found in log data.");
        return Vec::new();
    }

    // Filter blobs BEFORE deserialization (Aho-Corasick)
    let filtered_blobs = if let Some(q) = search {
        if q.is_empty() {
            event_blobs
        } else {
            let ac = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build([q])
                .unwrap();
            event_blobs
                .into_par_iter()
                .filter(|blob| ac.is_match(blob))
                .collect()
        }
    } else {
        event_blobs
    };

    let events_all: Vec<RadiusEvent> = filtered_blobs
        .into_par_iter()
        .filter_map(
            |blob| match quick_xml::de::from_reader::<&[u8], RadiusEvent>(&blob[..]) {
                Ok(ev) => Some(ev),
                Err(e) => {
                    tracing::error!(
                        "Failed to deserialize Event XML: {}. Blob: {}",
                        e,
                        String::from_utf8_lossy(&blob)
                    );
                    None
                }
            },
        )
        .collect();

    let mut groups: Vec<Vec<RadiusEvent>> = Vec::new();
    let mut class_map: HashMap<String, usize> = HashMap::new();

    for ev in events_all {
        let key_opt = ev
            .class
            .as_deref()
            .or(ev.acct_session_id.as_deref())
            .filter(|s| !s.is_empty());

        if let Some(k) = key_opt {
            if let Some(&idx) = class_map.get(k) {
                groups[idx].push(ev);
            } else {
                class_map.insert(k.to_string(), groups.len());
                groups.push(vec![ev]);
            }
        } else {
            groups.push(vec![ev]);
        }
    }

    let mut reqs: Vec<RadiusRequest> = groups.into_par_iter().map(|g| process_group(&g)).collect();

    // Reverse time sort is often desired for "latest" logs
    reqs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if reqs.len() > limit {
        reqs.truncate(limit);
    }
    reqs
}

pub fn process_group(group: &[RadiusEvent]) -> RadiusRequest {
    let mut req = RadiusRequest::default();
    for event in group {
        let p_type = event.packet_type.as_deref().unwrap_or("");
        if p_type == "1" || p_type == "4" {
            if let Some(val) = &event.timestamp {
                req.timestamp.clone_from(val);
            }
            if let Some(val) = &event.acct_session_id {
                req.session_id.clone_from(val);
            }
            if let Some(val) = &event.server {
                req.server.clone_from(val);
            }

            // FIX: Try Client-IP-Address first, then fallback to NAS-IP-Address
            if let Some(val) = &event.ap_ip {
                req.ap_ip.clone_from(val);
            } else if let Some(val) = &event.nas_ip {
                req.ap_ip.clone_from(val);
            }

            if let Some(val) = &event.client_friendly_name {
                req.ap_name.clone_from(val);
            } else if let Some(val) = &event.ap_name {
                req.ap_name.clone_from(val);
            }
            if let Some(val) = &event.mac {
                req.mac.clone_from(val);
            }
            if let Some(val) = &event.class {
                req.class_id.clone_from(val);
            }
            if req.req_type.is_empty() {
                req.req_type = map_packet_type(p_type);
            }

            if let Some(user) = &event.sam_account {
                req.user.clone_from(user);
            } else if let Some(user) = &event.user_name {
                req.user.clone_from(user);
            } else {
                req.user = "Unknown User".to_string();
            }
        } else {
            let this_resp_type = map_packet_type(p_type);
            let code = event.reason_code.as_deref().unwrap_or("0");
            if req.reason.is_empty() || code != "0" {
                req.resp_type = this_resp_type.clone();
                req.reason = map_reason(code);
            }
            match p_type {
                "2" => req.status = Some("success".to_string()),
                "3" => req.status = Some("fail".to_string()),
                "11" => req.status = Some("challenge".to_string()),
                _ => {}
            }
        }
    }
    req
}

/// Recherche ultra-rapide utilisant Aho-Corasick.
pub fn fast_search(reqs: &mut Vec<RadiusRequest>, query: &str) {
    if query.is_empty() {
        return;
    }
    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([query])
        .unwrap();
    reqs.retain(|r| {
        ac.is_match(&r.user)
            || ac.is_match(&r.mac)
            || ac.is_match(&r.ap_ip)
            || ac.is_match(&r.server)
            || ac.is_match(&r.reason)
    });
}
