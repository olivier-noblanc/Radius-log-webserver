use crate::api::handlers::logs::LogFile;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct LogFiltersProps {
    pub files: Vec<LogFile>,
    pub current_file: String,
    pub search_val: String,
}

#[component]
pub fn LogFilters(props: LogFiltersProps) -> Element {
    rsx! {
        form {
            id: "log-filters",
            "hx-get": "/api/logs/rows",
            "hx-target": "#log-table-container",
            "hx-swap": "innerHTML",
            "hx-trigger": "change from:select, change from:input[type=checkbox], input delay:500ms from:input[type=text]",
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
                    class: "cursor-pointer w-18 h-18"
                }
                label { r#for: "errorToggle", class: "error-only-label", "ERRORS ONLY" }
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
                    "EXPORT CSV"
                }
            }
        }
    }
}
