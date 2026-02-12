use dioxus::prelude::*;
use crate::core::models::RadiusRequest;

#[derive(Props, Clone, PartialEq)]
pub struct LogDetailProps {
    pub log: RadiusRequest,
    pub raw_json: String,
}

#[component]
pub fn LogDetail(props: LogDetailProps) -> Element {
    rsx! {
        div { class: "log-detail-content",
            div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-6",
                div { class: "detail-item",
                    div { class: "text-xxs text-muted uppercase", "Timestamp" }
                    div { class: "text-sm", "{props.log.timestamp}" }
                }
                div { class: "detail-item",
                    div { class: "text-xxs text-muted uppercase", "User" }
                    div { class: "text-sm font-bold text-primary", "{props.log.user}" }
                }
                div { class: "detail-item",
                    div { class: "text-xxs text-muted uppercase", "Status" }
                    div { 
                        class: if props.log.status.as_deref() == Some("fail") { "text-fail" } else { "text-success" },
                        "{props.log.resp_type}" 
                    }
                }
                div { class: "detail-item",
                    div { class: "text-xxs text-muted uppercase", "Reason" }
                    div { class: "text-sm italic", "{props.log.reason}" }
                }
            }
            div { class: "mt-4",
                div { class: "text-xxs text-muted uppercase mb-2", "Raw Data Stream" }
                pre { class: "bg-black/40 p-4 rounded border border-white/5 text-xxs font-mono overflow-x-auto custom-scrollbar",
                    "{props.raw_json}"
                }
            }
        }
    }
}
