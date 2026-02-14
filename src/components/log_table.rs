use crate::core::models::RadiusRequest;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct LogTableProps {
    pub logs: Vec<RadiusRequest>,
    pub sort_by: String,
    pub sort_desc: bool,
    pub column_order: Vec<String>,
}

#[component]
pub fn LogTable(props: LogTableProps) -> Element {
    let get_sort_desc = |col: &str| {
        if props.sort_by == col {
            if props.sort_desc {
                "false"
            } else {
                "true"
            }
        } else {
            "true"
        }
    };

    let render_sort_indicator = |col: &str| {
        if props.sort_by == col {
            if props.sort_desc {
                rsx! { span { class: "sort-indicator desc", " ↓" } }
            } else {
                rsx! { span { class: "sort-indicator asc", " ↑" } }
            }
        } else {
            rsx! { span { class: "sort-indicator hidden-opacity", " ↕" } }
        }
    };

    let all_cols = [
        ("timestamp", "TIMESTAMP"),
        ("req_type", "TYPE"),
        ("server", "SERVER"),
        ("ap_ip", "AP IP"),
        ("ap_name", "AP NAME"),
        ("mac", "MAC"),
        ("user", "USER"),
        ("resp_type", "RESULT"),
        ("reason", "DIAGNOSTICS"),
    ];

    // Build the ordered list of columns based on props.column_order
    let mut ordered_cols = Vec::new();
    for key in &props.column_order {
        if let Some(col) = all_cols.iter().find(|(k, _)| k == key) {
            ordered_cols.push(*col);
        }
    }
    // Add missing columns if any
    for col in all_cols {
        if !ordered_cols.iter().any(|(k, _)| k == &col.0) {
            ordered_cols.push(col);
        }
    }

    rsx! {
        div {
            id: "log-table-container",
            class: "glass-panel table-container",
            div { class: "table-controls mb-4 flex justify-between items-center",
                div { class: "flex gap-8",
                    span { class: "text-muted", "COLUMNS VISIBILITY:" }
                    div { class: "column-picker flex gap-8",
                        for (idx , (key , name)) in ordered_cols.iter().enumerate() {
                            label {
                                class: "column-checkbox",
                                draggable: "true",
                                "data-col-key": "{key}",
                                input {
                                    r#type: "checkbox",
                                    checked: true,
                                    class: "column-visibility-check",
                                    "data-col-idx": "{idx}",
                                    "data-col-key": "{key}"
                                }
                                " {name}"
                            }
                        }
                    }
                }
            }
            table { id: "logTable",
                thead {
                    tr {
                        for (key , name) in &ordered_cols {
                            th {
                                class: "sortable",
                                "data-col-key": "{key}",
                                "hx-get": "/api/logs/rows?sort_by={key}&sort_desc={get_sort_desc(key)}",
                                "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                                "hx-target": "#log-table-container",
                                "{name}"
                                {render_sort_indicator(key)}
                                div { class: "resizer" }
                            }
                        }
                    }
                }
                tbody { id: "logTableBody",
                    for log in props.logs {
                        tr {
                            class: "log-row cursor-pointer",
                            "hx-get": "/api/logs/detail?id={log.id.unwrap_or_default()}",
                            "hx-target": "#modalBody",
                            "hx-trigger": "click",

                            for (key , _) in &ordered_cols {
                                match *key {
                                    "timestamp" => rsx! { td { "data-col-key": "{key}", "{log.timestamp}" } },
                                    "req_type" => rsx! { td { "data-col-key": "{key}", "{log.req_type}" } },
                                    "server" => rsx! { td { "data-col-key": "{key}", "{log.server}" } },
                                    "ap_ip" => rsx! { td { "data-col-key": "{key}", "{log.ap_ip}" } },
                                    "ap_name" => rsx! { td { "data-col-key": "{key}", "{log.ap_name}" } },
                                    "mac" => rsx! { td { "data-col-key": "{key}", "{log.mac}" } },
                                    "user" => rsx! { td { "data-col-key": "{key}", "{log.user}" } },
                                    "resp_type" => {
                                        let status_class = match log.status.as_deref() {
                                            Some("fail") => "status-fail",
                                            Some("challenge") => "status-challenge",
                                            _ => "status-success",
                                        };
                                        let status_data = match log.status.as_deref() {
                                            Some("fail") => "fail",
                                            Some("challenge") => "challenge",
                                            _ => "success",
                                        };
                                        rsx! {
                                            td {
                                                "data-col-key": "{key}",
                                                class: "{status_class}",
                                                "data-status": "{status_data}",
                                                "{log.resp_type}"
                                            }
                                        }
                                    },
                                    "reason" => rsx! { td { "data-col-key": "{key}", "{log.reason}" } },
                                    _ => rsx! { td { "data-col-key": "{key}", "" } },
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
