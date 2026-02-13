use crate::api::handlers::stats::Stats;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct DashboardProps {
    pub stats: Stats,
}

#[component]
pub fn Dashboard(props: DashboardProps) -> Element {
    let rejection_count = props.stats.total_requests
        - (props.stats.total_requests as f64 * props.stats.success_rate / 100.0).round() as usize;
    let success_rate_rounded = props.stats.success_rate.round() as u32;

    rsx! {
        div { class: "dashboard-container grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 p-6 animate-fade-in",

            // Stat Card: Total Requests
            div { class: "stat-card glass-panel p-4 flex flex-col items-center justify-center",
                div { class: "text-xs text-muted uppercase tracking-widest mb-2", "Total Transactions" }
                div { class: "text-4xl font-bold tracking-tighter text-glow", "{props.stats.total_requests}" }
                div { class: "text-xxs mt-2 opacity-50", "24H ACTIVITY WINDOW" }
            }

            // Stat Card: Success Rate
            div { class: "stat-card glass-panel p-4 flex flex-col items-center justify-center highlight",
                div { class: "text-xs text-muted uppercase tracking-widest mb-2", "Efficiency Level" }
                div { class: "text-4xl font-bold tracking-tighter text-success", "{success_rate_rounded}%" }
                div { class: "w-full bg-white/5 h-1 mt-4 rounded-full overflow-hidden",
                    div { class: "bg-success h-full", style: "width: {success_rate_rounded}%" }
                }
            }

            // Stat Card: Rejections
            div { class: "stat-card glass-panel p-4 flex flex-col items-center justify-center",
                div { class: "text-xs text-muted uppercase tracking-widest mb-2", "Access Denied" }
                div { class: "text-4xl font-bold tracking-tighter text-fail", "{rejection_count}" }
                div { class: "text-xxs mt-2 opacity-50", "SECURITY REJECTIONS" }
            }

            // NEW: Security Health Status
            div {
                class: "stat-card glass-panel p-4 flex flex-col items-center justify-center relative overflow-hidden",
                class: if !props.stats.security_vulnerabilities.is_empty() { "animate-pulse border-red-500/50" } else { "" },

                div { class: "text-xs text-muted uppercase tracking-widest mb-2", "Security Status" }

                if props.stats.security_vulnerabilities.is_empty() {
                    div { class: "text-2xl font-bold text-success text-glow", "SECURE" }
                    div { class: "text-xxs mt-2 opacity-50", "NO CRITICAL THREATS" }
                } else {
                    div { class: "text-2xl font-bold text-fail text-glow", "ALERT" }
                    div { class: "text-xxs mt-2 text-fail animate-pulse", "{props.stats.security_vulnerabilities.len()} ISSUES DETECTED" }
                }

                // Overlay for critical alerts
                if !props.stats.security_vulnerabilities.is_empty() {
                    div { class: "absolute inset-0 bg-red-500/5 pointer-events-none" }
                }
            }

            // Chart Space
            div { class: "lg:col-span-4 glass-panel p-6 min-h-[16rem] flex flex-col relative overflow-hidden",
                if !props.stats.security_vulnerabilities.is_empty() {
                    div { class: "mb-4",
                        h4 { class: "text-xs font-bold text-fail tracking-widest mb-3 uppercase", "Critical Security Alerts" }
                        div { class: "flex flex-col gap-2",
                            for alert in &props.stats.security_vulnerabilities {
                                div { class: "text-xs p-2 bg-red-500/10 border-l-2 border-red-500 flex items-center gap-3",
                                    span { class: "text-fail", "!" }
                                    span { "{alert}" }
                                }
                            }
                        }
                    }
                } else {
                    div { class: "absolute inset-0 opacity-10 pointer-events-none",
                        svg { width: "100%", height: "100%", view_box: "0 0 1000 200", preserve_aspect_ratio: "none",
                            path {
                                d: "M0 150 Q 250 50, 500 150 T 1000 150",
                                fill: "none",
                                stroke: "var(--primary-glow)",
                                stroke_width: "2"
                            }
                        }
                    }
                    div { class: "text-center my-auto z-10",
                        div { class: "text-xs text-muted uppercase tracking-widest", "Live Performance Matrix" }
                        div { class: "text-2xl mt-2 font-light opacity-80", "LOGISTIC REGRESSION STABLE" }
                    }
                }
            }
        }
    }
}
