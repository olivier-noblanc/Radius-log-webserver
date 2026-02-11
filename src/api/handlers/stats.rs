use actix_web::{web, HttpResponse, HttpRequest, Responder};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use crate::infrastructure::cache::LogCache;
use crate::utils::security::is_authorized;

#[derive(Serialize, Clone, PartialEq)]
pub struct Stats {
    pub total_requests: usize,
    pub success_rate: f64,
    pub active_users: usize,
    pub rejections_by_hour: Vec<(String, u32)>,
    pub top_users: Vec<(String, u32)>,
    pub top_reasons: Vec<(String, u32)>,
    pub svg_line_points: String,
    pub pie_gradient: String,
    pub reasons_legend: Vec<(String, String, u32)>,
}

pub async fn get_stats(req: HttpRequest, cache: web::Data<Arc<LogCache>>) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }
    let stats = get_stats_data(&cache);
    HttpResponse::Ok().json(stats)
}

pub fn get_stats_data(cache: &LogCache) -> Stats {
    let reqs = cache.read();
    let total_requests = reqs.len();
    let mut success_count = 0;
    let mut unique_users = std::collections::HashSet::new();
    let mut rejections_map: HashMap<String, u32> = HashMap::new();
    let mut user_failures: HashMap<String, u32> = HashMap::new();
    let mut reason_failures: HashMap<String, u32> = HashMap::new();

    for r in &reqs {
        unique_users.insert(r.user.clone());

        let is_accept = r.resp_type.contains("Accept");
        let is_reject = r.resp_type.contains("Reject");

        if is_accept {
            success_count += 1;
        }

        if is_reject {
            if let Some(time_part) = r.timestamp.split_whitespace().last() {
                if let Some(hour) = time_part.split(':').next() {
                    *rejections_map.entry(format!("{}:00", hour)).or_insert(0) += 1;
                }
            }
            *user_failures.entry(r.user.clone()).or_insert(0) += 1;
            *reason_failures.entry(r.reason.clone()).or_insert(0) += 1;
        }
    }

    let success_rate = if total_requests > 0 {
        (success_count as f64 / total_requests as f64) * 100.0
    } else {
        0.0
    };

    let mut rejections_by_hour: Vec<_> = rejections_map.into_iter().collect();
    rejections_by_hour.sort_by(|a, b| a.0.cmp(&b.0));

    let mut top_users: Vec<_> = user_failures.into_iter().collect();
    top_users.sort_by_key(|b| std::cmp::Reverse(b.1));
    top_users.truncate(10);

    let mut top_reasons: Vec<_> = reason_failures.into_iter().collect();
    top_reasons.sort_by_key(|b| std::cmp::Reverse(b.1));
    top_reasons.truncate(10);

    // --- CALCULS SVG / CSS POUR SSR ---
    let max_rejects = rejections_by_hour.iter().map(|x| x.1).max().unwrap_or(1) as f32;
    let mut svg_line_points = String::new();
    for (i, (_hour, count)) in rejections_by_hour.iter().enumerate() {
        let x = i as f32 * (400.0 / 23.0);
        let y = 100.0 - (*count as f32 / max_rejects * 100.0);
        svg_line_points.push_str(&format!("{:.1},{:.1} ", x, y));
    }

    let colors = ["#dc3545", "#fd7e14", "#ffc107", "#198754", "#0dcaf0", "#6f42c1", "#6610f2", "#e83e8c"];
    let mut pie_gradient = String::new();
    let mut current_percent = 0.0;
    let total_reasons_count: u32 = top_reasons.iter().map(|x| x.1).sum();
    let mut reasons_legend = Vec::new();

    for (i, (reason, count)) in top_reasons.iter().enumerate() {
        let color = colors[i % colors.len()];
        let percent = (*count as f32 / total_reasons_count as f32) * 100.0;
        let next_percent = current_percent + percent;
        if i > 0 { pie_gradient.push_str(", "); }
        pie_gradient.push_str(&format!("{} {:.1}% {:.1}%", color, current_percent, next_percent));
        reasons_legend.push((reason.clone(), color.to_string(), *count));
        current_percent = next_percent;
    }

    Stats {
        total_requests,
        success_rate,
        active_users: unique_users.len(),
        rejections_by_hour,
        top_users,
        top_reasons,
        svg_line_points,
        pie_gradient,
        reasons_legend,
    }
}
