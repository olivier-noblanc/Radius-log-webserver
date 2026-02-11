use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HeaderProps {
    pub build_version: String,
    pub theme: String,
}

#[component]
pub fn Header(props: HeaderProps) -> Element {
    let theme_data = format!(r#"{{ 
                theme: '{}', 
                liveConnected: false,
                ws: null,
                
                init() {{
                    this.connectWs();
                }},
                
                connectWs() {{
                    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
                    this.ws = new WebSocket(`${{proto}}//${{location.host}}/ws`);
                    
                    this.ws.onopen = () => {{ this.liveConnected = true; }};
                    this.ws.onclose = () => {{
                        this.liveConnected = false;
                        setTimeout(() => this.connectWs(), 5000);
                    }};
                    this.ws.onmessage = () => {{
                        htmx.ajax('GET', '/api/logs/rows', '#logTableBody');
                    }};
                }},
                
                toggleLive() {{
                    if (this.ws && this.ws.readyState === WebSocket.OPEN) {{
                        this.ws.close();
                    }} else {{
                        this.connectWs();
                    }}
                }}
            }}"#, props.theme);

    let nav_logs_click = r#"
        document.getElementById('view-logs').style.display = 'block';
        document.getElementById('view-dashboard').style.display = 'none';
        $el.classList.add('active');
        document.getElementById('btn-nav-dashboard').classList.remove('active');
    "#;

    let nav_dashboard_click = r#"
        document.getElementById('view-logs').style.display = 'none';
        document.getElementById('view-dashboard').style.display = 'block';
        $el.classList.add('active');
        document.getElementById('btn-nav-logs').classList.remove('active');
    "#;

    let theme_change = r#"
        fetch('/api/theme?theme=' + theme)
            .then(r => r.text())
            .then(html => {
                document.getElementById('theme-css').innerHTML = html;
                document.documentElement.setAttribute('data-theme', theme);
            });
    "#;

    let live_dot_class = "{ 'active': liveConnected }";

    rsx! {
        header { 
            class: "main-header glass-panel mb-6",
            "x-data": theme_data,
            
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
                button { 
                    id: "btn-nav-logs",
                    class: "btn-glass btn-nav active", 
                    "hx-get": "/api/logs/rows",
                    "hx-target": "#logTableBody",
                    "hx-swap": "innerHTML",
                    "@click": nav_logs_click,
                    "LOG STREAM"
                }
                button { 
                    id: "btn-nav-dashboard",
                    class: "btn-glass btn-nav", 
                    "hx-get": "/api/dashboard",
                    "hx-target": "#view-dashboard",
                    "hx-swap": "innerHTML",
                    "@click": nav_dashboard_click,
                    "ANALYTICS"
                }
            }

            div { class: "flex items-center gap-4 controls-right",
                select { 
                    id: "themeSelect", 
                    name: "theme", 
                    class: "input-glass theme-select",
                    "x-model": "theme",
                    "@change": theme_change,
                    
                    option { value: "onyx-glass", selected: props.theme == "onyx-glass", "FLAGSHIP // ONYX GLASS" }
                    option { value: "cyber-tactical", selected: props.theme == "cyber-tactical", "FLAGSHIP // CYBER TACTICAL" }
                    option { value: "neon", selected: props.theme == "neon", "NEON // 2077" }
                    option { value: "dsfr", selected: props.theme == "dsfr", "RÉPUBLIQUE // FR" }
                    option { value: "compact", selected: props.theme == "compact", "INDUSTRIAL // DENSE" }
                    option { value: "terminal", selected: props.theme == "terminal", "TERMINAL // SSH" }
                    option { value: "xp", selected: props.theme == "xp", "WINDOWS XP // LUNA" }
                    option { value: "win31", selected: props.theme == "win31", "WINDOWS 3.1 // LEGACY" }
                    option { value: "win95", selected: props.theme == "win95", "WINDOWS CHICAGO // 95" }
                    option { value: "macos", selected: props.theme == "macos", "MACINTOSH // CLASSIC" }
                    option { value: "dos", selected: props.theme == "dos", "MS-DOS // COMSPEC" }
                    option { value: "c64", selected: props.theme == "c64", "COMMODORE // 64" }
                    option { value: "nes", selected: props.theme == "nes", "NINTENDO // 8-BIT" }
                    option { value: "snes", selected: props.theme == "snes", "S-NINTENDO // 16-BIT" }
                    option { value: "aero", selected: props.theme == "aero", "AERO // VISTA" }
                    option { value: "amber", selected: props.theme == "amber", "AMBER // MONO" }
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

                div { 
                    id: "statusBadge", 
                    class: "status-badge",
                    "x-text": "liveConnected ? 'CONNECTED' : 'DISCONNECTED'",
                    ":style": "liveConnected ? 'color: #39ff14' : 'color: #ff3131'"
                }

                button { 
                    class: "btn-glass", 
                    "@click": "toggleLive()",
                    div { 
                        class: "live-dot",
                        ":class": live_dot_class
                    }
                    span { 
                        class: "live-label",
                        "x-text": "liveConnected ? 'LIVE' : 'OFFLINE'",
                        ":style": "liveConnected ? 'color: #39ff14' : 'color: var(--text-muted)'"
                    }
                }
            }
        }
    }
}
