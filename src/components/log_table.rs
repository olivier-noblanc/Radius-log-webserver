use crate::core::models::RadiusRequest;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct LogTableProps {
    pub logs: Vec<RadiusRequest>,
    pub sort_by: String,
    pub sort_desc: bool,
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

    rsx! {
        div {
            id: "log-table-container",
            class: "glass-panel table-container",
            div { class: "table-controls mb-4 flex justify-between items-center",
                div { class: "flex gap-8",
                    span { class: "text-muted", "COLUMNS VISIBILITY:" }
                    div { class: "column-picker flex gap-8",
                        for (idx , name) in [
                            "TIMESTAMP", "TYPE", "SERVER", "AP IP", "AP NAME", "MAC", "USER", "RESULT", "DIAGNOSTICS"
                        ].iter().enumerate()
                        {
                            label { class: "column-checkbox",
                                input {
                                    r#type: "checkbox",
                                    checked: true,
                                    "onchange": "toggleColumn({idx})",
                                    "data-col-idx": "{idx}"
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
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=timestamp&sort_desc={get_sort_desc(\"timestamp\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "TIMESTAMP"
                            {render_sort_indicator("timestamp")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=req_type&sort_desc={get_sort_desc(\"req_type\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "TYPE"
                            {render_sort_indicator("req_type")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=server&sort_desc={get_sort_desc(\"server\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "SERVER"
                            {render_sort_indicator("server")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=ap_ip&sort_desc={get_sort_desc(\"ap_ip\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "AP IP"
                            {render_sort_indicator("ap_ip")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=ap_name&sort_desc={get_sort_desc(\"ap_name\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "AP NAME"
                            {render_sort_indicator("ap_name")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=mac&sort_desc={get_sort_desc(\"mac\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "MAC"
                            {render_sort_indicator("mac")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=user&sort_desc={get_sort_desc(\"user\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "USER"
                            {render_sort_indicator("user")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=resp_type&sort_desc={get_sort_desc(\"resp_type\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "RESULT"
                            {render_sort_indicator("resp_type")}
                            div { class: "resizer" }
                        }
                        th {
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=reason&sort_desc={get_sort_desc(\"reason\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#log-table-container",
                            "DIAGNOSTICS"
                            {render_sort_indicator("reason")}
                            div { class: "resizer" }
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
                            "hx-on:click": "window.location.hash='detailModal'",

                            td { "{log.timestamp}" }
                            td { "{log.req_type}" }
                            td { "{log.server}" }
                            td { "{log.ap_ip}" }
                            td { "{log.ap_name}" }
                            td { "{log.mac}" }
                            td { "{log.user}" }
                            td {
                                class: match log.status.as_deref() {
                                    Some("fail") => "status-fail",
                                    Some("challenge") => "status-challenge",
                                    _ => "status-success",
                                },
                                "data-status": match log.status.as_deref() {
                                    Some("fail") => "fail",
                                    Some("challenge") => "challenge",
                                    _ => "success",
                                },
                                "{log.resp_type}"
                            }
                            td { "{log.reason}" }
                        }
                    }
                }
            }
        }
    }
}
