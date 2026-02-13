use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct LayoutProps {
    pub title: String,
    pub theme: String,
    pub build_version: String,
    pub git_sha: String,
    pub is_authorized: bool,
    pub css_files: Vec<String>,
    pub children: Element,
}

#[component]
pub fn Layout(props: LayoutProps) -> Element {
    rsx! {
        head {
            meta { charset: "utf-8" }
            meta { name: "viewport", content: "width=device-width, initial-scale=1.0" }
            title { "{props.title}" }
            
            // Base CSS
            link { rel: "stylesheet", href: "/css/style.css" }
            link { rel: "stylesheet", href: "/css/fonts.css" }
            
            // Theme specific CSS files (Dynamic injection)
            for file in &props.css_files {
                link { rel: "stylesheet", href: "{file}" }
            }

            // HTMX (LOCAL) & App JS
            script { src: "/js/htmx.min.js" }
            script { src: "/js/app.js" }
        }
        body { "data-theme": "{props.theme}",
            // Login Gate (Human Check) if not authorized
            if !props.is_authorized {
                div { id: "human-gate",
                    div { class: "gate-content",
                        h1 { class: "gate-logo", "RADIUS LOG CORE" }
                        p { class: "gate-subtitle", "SECURE CONTROL" }
                        a { href: "/api/login?logged=yes&theme={props.theme}", class: "btn-glass btn-primary mt-6", "AUTHENTICATE" }
                    }
                }
            }

            // Main Application Root
            div { id: "app-root", class: if !props.is_authorized { "hidden" } else { "visible" },
                // Global Modals
                crate::components::modals::SecurityModal {
                    is_authorized: props.is_authorized
                }
                crate::components::modals::DetailModal {}

                // Header Navigation
                crate::components::header::Header {
                    build_version: props.build_version.clone(),
                    theme: props.theme.clone(),
                }

                // Main Content Area
                main { class: "container app-wrapper",
                    {props.children}
                }
                
                // Global Loader
                div { id: "global-loader",
                    div { class: "loader-progress-bar" }
                    div { class: "loader-box",
                        div { class: "loader-icon",
                        // === MACINTOSH SYSTEM 7 HOURGLASS (NO CONTAINER) ===
                        // === MACINTOSH SYSTEM 7 WATCH (PIXEL ART) ===
                        div { class: "macos-watch",
                            div { class: "macos-watch-hands" }
                        }
                        div { class: "prof-loader",
                            span {}
                            span {}
                        }
                            
                            // Windows 3.1 Loader (Hourglass)
                            div { class: "win31-hourglass", style: "display: none;", "⏳" }
                            
                        }
                        // Loader text (varies by theme)
                        div { class: "loader-text",
                            div { class: "loader-title", "PROCESSING" }
                            div { class: "loader-sub", "Fetching Data..." }
                        }
                    }
                }
            }
        }
    }
}