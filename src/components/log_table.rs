use dioxus::prelude::*;
use crate::core::models::RadiusRequest;

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
            if props.sort_desc { "false" } else { "true" }
        } else {
            "true"
        }
    };

    rsx! {
        div { class: "glass-panel table-container",
            table { id: "logTable",
                thead {
                    tr {
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=timestamp&sort_desc={get_sort_desc(\"timestamp\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "TIMESTAMP"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=req_type&sort_desc={get_sort_desc(\"req_type\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "TYPE"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=server&sort_desc={get_sort_desc(\"server\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "SERVER"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=ap_ip&sort_desc={get_sort_desc(\"ap_ip\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "AP IP"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=ap_name&sort_desc={get_sort_desc(\"ap_name\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "AP NAME"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=mac&sort_desc={get_sort_desc(\"mac\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "MAC"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=user&sort_desc={get_sort_desc(\"user\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "USER"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=resp_type&sort_desc={get_sort_desc(\"resp_type\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "RESULT"
                            div { class: "resizer" }
                        }
                        th { 
                            class: "sortable",
                            "hx-get": "/api/logs/rows?sort_by=reason&sort_desc={get_sort_desc(\"reason\")}",
                            "hx-include": "#log-filters :not([name='sort_by']):not([name='sort_desc'])",
                            "hx-target": "#logTableBody",
                            "DIAGNOSTICS"
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
                            
                            td { "{log.timestamp}" }
                            td { "{log.req_type}" }
                            td { "{log.server}" }
                            td { "{log.ap_ip}" }
                            td { "{log.ap_name}" }
                            td { "{log.mac}" }
                            td { "{log.user}" }
                            td { 
                                class: if log.status.as_deref() == Some("fail") { "status-fail" } else { "status-success" },
                                "data-status": if log.status.as_deref() == Some("fail") { "fail" } else { "success" },
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
