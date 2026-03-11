use crate::api::handlers::logs::LogFile;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct LogFiltersProps {
    pub files: Vec<LogFile>,
    pub current_file: String,
    pub search_val: String,
    pub error_only: bool,
}

#[component]
pub fn LogFilters(props: LogFiltersProps) -> Element {
    rsx! {
        form {
            id: "log-filters",
            "hx-get": "/api/logs/rows",
            "hx-target": "#log-table-container",
            "hx-swap": "innerHTML",
            "hx-trigger": "submit, change from:select, change from:input[type=checkbox]",
            "hx-indicator": "#global-loader",
            class: "flex items-center mb-4 glass-panel panel-main",

            div { class: "flex-grow",
                select { id: "fileSelect", name: "file", class: "input-glass",
                    for file in props.files {
                        option {
                            value: "{file.path}",
                            selected: file.path == props.current_file,
                            "{file.name} ({file.formatted_size})"
                        }
                    }
                }
            }
            div { class: "flex-grow",
                input {
                    r#type: "text",
                    id: "searchInput",
                    name: "search",
                    class: "input-glass",
                    placeholder: "Search (User, IP, Reason)...",
                    value: "{props.search_val}"
                }
            }
            div { class: "flex items-center ml-4 gap-8 text-xs text-muted",
                input {
                    r#type: "checkbox",
                    id: "errorToggle",
                    name: "error_only",
                    value: "true",
                    checked: "{props.error_only}",
                    class: "cursor-pointer w-18 h-18"
                }
                label { r#for: "errorToggle", class: "error-only-label", "ERRORS ONLY" }
            }

            // Notification toggle (Minimalist)
            div { class: "flex items-center ml-4 gap-8 text-xs text-muted",
                input {
                    r#type: "checkbox",
                    id: "notifToggle",
                    class: "cursor-pointer w-18 h-18"
                }
                label { r#for: "notifToggle", class: "error-only-label", "ALERTS" }
            }
            div { id: "notifWarning", class: "ml-4 text-[10px] text-yellow-500",
                "Notifications require HTTPS (or localhost). If you use IIS proxy, ensure URL Rewrite/ARR and HTTPS binding are OK."
            }

            input { r#type: "hidden", id: "sort_by", name: "sort_by", value: "timestamp" }
            input { r#type: "hidden", id: "sort_desc", name: "sort_desc", value: "true" }

            div {
                button {
                    r#type: "submit",
                    class: "btn-glass btn-primary",
                    id: "loadBtn",
                    "hx-indicator": "#global-loader",
                    "REFRESH"
                }
                a {
                    href: "/api/export?file={props.current_file}&search={props.search_val}",
                    class: "btn-glass",
                    id: "exportBtn",
                    "hx-indicator": "#global-loader",
                    "EXPORT EXCEL"
                }
            }
        }
    }
}
