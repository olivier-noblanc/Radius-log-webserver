use dioxus::prelude::*;
use crate::components::header::Header;
use crate::components::modals::{SecurityModal, DetailModal};

#[derive(Props, Clone, PartialEq)]
pub struct LayoutProps {
    pub title: String,
    pub theme: String,
    pub build_version: String,
    pub git_sha: String,
    pub css_files: Vec<String>,
    pub is_authorized: bool,
    pub children: Element,
}

#[component]
pub fn Layout(props: LayoutProps) -> Element {
    rsx! {
        head {
            meta { charset: "UTF-8" }
            meta { name: "viewport", content: "width=device-width, initial-scale=1.0, viewport-fit=cover" }
            meta { name: "description", content: "Enterprise RADIUS Log Management System - Real-time monitoring and analytics." }
            meta { name: "author", content: "Radius Log Team" }
            meta { name: "theme-color", content: "#050505" }
            meta { name: "robots", content: "noindex, nofollow" }
            meta { name: "referrer", content: "no-referrer" }
            // Tentative de déblocage SES : Lockdown provient souvent d'une extension (MetaMask)
            // qui gèle les intrinsèques. On s'assure que rien dans nos headers ne l'encourage.
            title { "{props.title}" }

            link { rel: "preconnect", href: "https://fonts.googleapis.com" }
            link { rel: "preconnect", href: "https://fonts.gstatic.com", crossorigin: "true" }
            link {
                href: "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400;500&family=Orbitron:wght@400;700&family=Rajdhani:wght@400;700&family=Fira+Code:wght@400;700&family=Press+Start+2P&family=VT323&display=swap",
                rel: "stylesheet"
            }
            link { rel: "stylesheet", href: "/css/bootstrap-icons.min.css" }
            link { rel: "icon", r#type: "image/svg+xml", href: "/favicon.svg" }

            script { 
                defer: true,
                src: "/js/cdn/alpine.js"
            }
            script {
                r#type: "text/javascript",
                dangerous_inner_html: r#"
                    document.addEventListener('alpine:init', () => {{
                        Alpine.data('themeHandler', function() {{
                            return {{
                                theme: '',
                                liveConnected: false,
                                statusText: 'DISCONNECTED',
                                statusStyle: 'color: #ff3131',
                                liveLabel: 'OFFLINE',
                                liveStyle: 'color: var(--text-muted)',
                                liveDotClass: '',
                                ws: null,
                                
                                init() {{
                                    // Read initial theme from data attribute
                                    this.theme = this.$el.dataset.initialTheme || 'onyx-glass';
                                    this.connectWs();
                                }},
                                
                                connectWs() {{
                                    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
                                    this.ws = new WebSocket(`${{proto}}//${{location.host}}/ws`);
                                    
                                    this.ws.onopen = () => {{ 
                                        this.liveConnected = true;
                                        this.statusText = 'CONNECTED';
                                        this.statusStyle = 'color: #39ff14';
                                        this.liveLabel = 'LIVE';
                                        this.liveStyle = 'color: #39ff14';
                                        this.liveDotClass = 'active';
                                    }};
                                    
                                    this.ws.onclose = () => {{
                                        this.liveConnected = false;
                                        this.statusText = 'DISCONNECTED';
                                        this.statusStyle = 'color: #ff3131';
                                        this.liveLabel = 'OFFLINE';
                                        this.liveStyle = 'color: var(--text-muted)';
                                        this.liveDotClass = '';
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
                                }},

                                changeTheme() {{
                                    fetch('/api/theme?theme=' + this.theme)
                                        .then(r => r.text())
                                        .then(html => {{
                                            document.getElementById('theme-css').innerHTML = html;
                                            document.documentElement.setAttribute('data-theme', this.theme);
                                            htmx.ajax('GET', '/api/logs/rows', '#logTableBody');
                                        }});
                                }}
                            }}
                        }});
                    }});
                "#
            }

            for css in props.css_files {
                link { 
                    id: if css.contains("/themes/") { "theme-link" } else { "" },
                    rel: "stylesheet", 
                    href: "{css}?v={props.git_sha}"
                }
            }
            div { id: "theme-css" }

            svg { width: "0", height: "0", style: "position: absolute;",
                defs {
                    pattern { id: "nes-pixels", x: "4", y: "4", width: "4", height: "4", pattern_units: "userSpaceOnUse",
                        rect { x: "0", y: "0", width: "2", height: "2", fill: "#ff0000", opacity: "0.1" }
                        rect { x: "2", y: "2", width: "2", height: "2", fill: "#ff0000", opacity: "0.1" }
                    }
                    pattern { id: "snes-bevel", x: "2", y: "2", width: "2", height: "2", pattern_units: "userSpaceOnUse",
                        rect { x: "0", y: "0", width: "1", height: "1", fill: "#ffffff", opacity: "0.1" }
                        rect { x: "1", y: "1", width: "1", height: "1", fill: "#000000", opacity: "0.2" }
                    }
                }
            }
        }
        body {
            "data-theme": "{props.theme}",
            
            if !props.is_authorized {
                div { 
                    id: "human-gate",
                    div { class: "gate-content",
                        h1 { 
                            class: "glitch-text gate-logo", 
                            "data-text": "HUMAN GATE",
                            "HUMAN GATE" 
                        }
                        p { class: "gate-subtitle", "SECURED ACCESS ONLY // IDENTITY VERIFICATION REQUIRED" }
                        a { 
                            href: "/api/login", 
                            class: "btn-glass btn-primary mt-6",
                            style: "padding: 0.8rem 2.5rem; font-size: 1rem; border-width: 2px;",
                            "INITIALIZE AUTHENTICATION" 
                        }
                    }
                }
            }

            div { 
                id: "app-root", 
                class: "app-root",
                class: if props.is_authorized { "visible" } else { "" },
                
                div { class: "crt-overlay" }
                div { class: "scanlines" }

                Header { 
                    build_version: props.build_version.clone(), 
                    theme: props.theme.clone()
                }

                {props.children}

                div { id: "view-dashboard", style: "display: none;" }

                SecurityModal {}
                DetailModal {}
            }
            script { src: "/js/htmx.min.js" }
            script { src: "/js/app.js", defer: "true" }
        }
    }
}
