use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HeaderProps {
    pub build_version: String,
    pub theme: String,
}

#[component]
pub fn Header(props: HeaderProps) -> Element {
    rsx! {
        header { 
            class: "main-header glass-panel mb-6",
            
            div { class: "flex flex-col",
                a { href: "/", class: "brand-logo",
                    svg { 
                        width: "24", height: "24", view_box: "0 0 24 24", 
                        fill: "none", stroke: "currentColor", stroke_width: "2",
                        stroke_linecap: "round", stroke_linejoin: "round",
                        path { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }
                        path { d: "M8 12h8" }
                        path { d: "M12 8v8" }
                    }
                    " RADIUS // LOG CORE"
                }
                div { class: "architect-info",
                    "SYSTEM ARCHITECT: "
                    span { class: "architect-name", "OLIVIER NOBLANC" }
                    " // {props.build_version}"
                }
            }

            nav { 
                class: "nav-main",
                
                // LOGS button - Pure HTMX
                button { 
                    id: "btn-nav-logs",
                    class: "btn-glass btn-nav active",
                    "hx-get": "/api/logs/rows",
                    "hx-target": "#log-table-container",
                    "hx-swap": "innerHTML",
                    "hx-trigger": "click",
                    "hx-indicator": "#global-loader",
                    "hx-on::after-request": r#"
                        document.getElementById('view-logs').style.display='block';
                        document.getElementById('view-dashboard').style.display='none';
                        this.classList.add('active');
                        document.getElementById('btn-nav-dashboard').classList.remove('active');
                    "#,
                    "LOG STREAM" 
                }
                
                // DASHBOARD button - Pure HTMX
                button { 
                    id: "btn-nav-dashboard",
                    class: "btn-glass btn-nav",
                    "hx-get": "/api/dashboard",
                    "hx-target": "#view-dashboard",
                    "hx-swap": "innerHTML",
                    "hx-trigger": "click",
                    "hx-indicator": "#global-loader",
                    "hx-on::after-request": r#"
                        document.getElementById('view-logs').style.display='none';
                        document.getElementById('view-dashboard').style.display='block';
                        this.classList.add('active');
                        document.getElementById('btn-nav-logs').classList.remove('active');
                    "#,
                    "ANALYTICS" 
                }
            }

            div { class: "flex items-center gap-4 controls-right",
                
                                  select { 
                        id: "themeSelect",
                        name: "theme",
                        class: "input-glass theme-select",
                        "hx-get": "/api/theme",
                        "hx-trigger": "change",
                        "hx-include": "this",
                        "hx-indicator": "#global-loader",
                        "hx-swap": "none",
                        "hx-on::after-request": "window.location.reload();",
                        
                        option { value: "onyx-glass", selected: props.theme == "onyx-glass", "[FLAGSHIP] Onyx Glass" }
                        option { value: "light", selected: props.theme == "light", "[LIGHT] Professional" }
                        option { value: "dark", selected: props.theme == "dark", "[DARK] OLED Mode" }
                        option { value: "neon", selected: props.theme == "neon", "[NEON] Cyberpunk" }

                        optgroup { label: "--- LEGACY SYSTEMS ---",
                            option { value: "win31", selected: props.theme == "win31", "Windows 3.1" }
                            option { value: "xp", selected: props.theme == "xp", "Windows XP" }
                            option { value: "macos", selected: props.theme == "macos", "Macintosh Classic" }
                        }

                        optgroup { label: "--- SPECIALIZED ---",
                            option { value: "terminal", selected: props.theme == "terminal", "Terminal / SSH" }
                            option { value: "compact", selected: props.theme == "compact", "Compact / Dense" }
                            option { value: "dsfr", selected: props.theme == "dsfr", "Republique Francaise" }
                        }
                    }
                    
                a { 
                    href: "#securityModal",
                    class: "btn-glass btn-audit",
                    svg { 
                        width: "16", height: "16", view_box: "0 0 24 24", 
                        fill: "none", stroke: "currentColor", stroke_width: "2",
                        path { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }
                    }
                    " SECURITY AUDIT"
                }

                div { id: "statusBadge", class: "status-badge", "DISCONNECTED" }
            }
        }
    }
}


