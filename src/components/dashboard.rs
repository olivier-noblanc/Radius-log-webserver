use dioxus::prelude::*;
use crate::api::handlers::stats::Stats;

#[derive(Props, Clone, PartialEq)]
pub struct DashboardProps {
    pub stats: Stats,
}

#[component]
pub fn Dashboard(props: DashboardProps) -> Element {
    let rejection_count = props.stats.total_requests - (props.stats.total_requests as f64 * props.stats.success_rate / 100.0).round() as usize;
    let success_rate_rounded = props.stats.success_rate.round() as u32;

    rsx! {
        div { class: "dashboard-container grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 p-6 animate-fade-in",
            
            // Stat Card: Total Requests
            div { class: "stat-card glass-panel p-4 flex flex-col items-center justify-center",
                div { class: "text-xs text-muted uppercase tracking-widest mb-2", "Total Transactions" }
                div { class: "text-4xl font-bold tracking-tighter text-glow", "{props.stats.total_requests}" }
                div { class: "text-[10px] mt-2 opacity-50", "24H ACTIVITY WINDOW" }
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
                div { class: "text-[10px] mt-2 opacity-50", "SECURITY REJECTIONS" }
            }

            // Stat Card: Active Users
            div { class: "stat-card glass-panel p-4 flex flex-col items-center justify-center",
                div { class: "text-xs text-muted uppercase tracking-widest mb-2", "Concurrent Clients" }
                div { class: "text-4xl font-bold tracking-tighter text-primary", "{props.stats.active_users}" }
                div { class: "text-[10px] mt-2 opacity-50", "UNIQUE SAM-ACCOUNT IDENTIFIED" }
            }

            // Chart Space
            div { class: "lg:col-span-4 glass-panel p-6 h-64 flex items-center justify-center relative overflow-hidden",
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
                div { class: "text-center z-10",
                    div { class: "text-xs text-muted uppercase tracking-widest", "Live Performance Matrix" }
                    div { class: "text-2xl mt-2 font-light opacity-80", "LOGISTIC REGRESSION STABLE" }
                }
            }
        }
    }
}
