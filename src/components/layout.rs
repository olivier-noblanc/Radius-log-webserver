use dioxus::prelude::*;
use crate::components::header::Header;
use crate::components::footer::{Footer, GlobalLoader};
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
            title { "{props.title}" }

            link { rel: "preconnect", href: "https://fonts.googleapis.com" }
            link { rel: "preconnect", href: "https://fonts.gstatic.com", crossorigin: "true" }
            link {
                href: "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400;500&family=Orbitron:wght@400;700&family=Rajdhani:wght@400;700&family=Fira+Code:wght@400;700&family=Press+Start+2P&family=VT323&display=swap",
                rel: "stylesheet"
            }
            link { rel: "stylesheet", href: "/css/bootstrap-icons.min.css" }
            link { rel: "icon", r#type: "image/svg+xml", href: "/favicon.svg" }

            div { id: "theme-css", style: "display: contents;",
                for css in props.css_files {
                    link { 
                        id: if css.contains("/themes/") { "theme-link" } else { "" },
                        rel: "stylesheet", 
                        href: "{css}?v={props.git_sha}" 
                    }
                }
            }

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
                GlobalLoader {}
                Footer {}
            }
            script { src: "/js/htmx.min.js" }
            script { src: "/js/app.js", defer: "true" }
        }
    }
}
