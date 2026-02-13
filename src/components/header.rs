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
                    // Icône LOGO Pixelisée (System 7)
                    svg { 
                        width: "24", height: "24", view_box: "0 0 24 24", 
                        fill: "none", stroke: "currentColor", stroke_width: "2",
                        // Attributs pour le rendu pixelisé net
                        shape_rendering: "crispEdges", 
                        stroke_linejoin: "miter",
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
                        const l = document.getElementById('view-logs'); if(l) l.style.display='block';
                        const d = document.getElementById('view-dashboard'); if(d) d.style.display='none';
                        const a = document.getElementById('view-audit'); if(a) a.style.display='none';
                        this.classList.add('active');
                        const bl = document.getElementById('btn-nav-dashboard'); if(bl) bl.classList.remove('active');
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
                        const l = document.getElementById('view-logs'); if(l) l.style.display='none';
                        const d = document.getElementById('view-dashboard'); if(d) d.style.display='block';
                        const a = document.getElementById('view-audit'); if(a) a.style.display='none';
                        this.classList.add('active');
                        const bl = document.getElementById('btn-nav-logs'); if(bl) bl.classList.remove('active');
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

                    option { value: "win31", selected: props.theme == "win31", "Windows 3.1" }
                    option { value: "macos", selected: props.theme == "macos", "Macintosh Classic" }
                }
                    
                a { 
                    href: "#securityModal",
                    class: "btn-glass btn-audit",
                    
                    // Icône SÉCURITÉ Pixelisée (Bouclier)
                    svg { 
                        width: "20", height: "20", view_box: "0 0 24 24", 
                        fill: "none", stroke: "currentColor", stroke_width: "2",
                        // Attributs pour le rendu pixelisé net
                        shape_rendering: "crispEdges", 
                        stroke_linecap: "square", 
                        stroke_linejoin: "miter",
                        path { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }
                    }
                    
                    " SECURITY AUDIT"
                }

                div { id: "statusBadge", class: "status-badge", "DISCONNECTED" }
            }
        }
    }
}