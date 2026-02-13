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
                div { id: "global-loader",
                    div { class: "loader-progress-bar" }
                    div { class: "loader-box",
                        div { class: "loader-icon",
                            div { class: "neon-ring", style: "display: none;" }
                            div { class: "win31-hourglass", style: "display: none;", "⏳" }
                             div { class: "macos-watch", style: "display: none;",
                               // Dans la partie loader (à côté de neon-ring, etc.)
svg {
    class: "macos-watch",
    "view-box": "0 0 32 32",
    "shape-rendering": "crispEdges", // IMPORTANT : Donne l'aspect pixelisé/net
    width: "32",
    height: "32",
    
    // Le cadran de la montre
    circle {
        cx: "16",
        cy: "16",
        r: "14",
        fill: "none",
        stroke: "black",
        "stroke-width": "2"
    }
    // Boutons de la montre (haut et bas)
    rect { x: "14", y: "0", width: "4", height: "2", fill: "black" }
    rect { x: "15", y: "28", width: "2", height: "4", fill: "black" }
    
    // L'aiguille des heures (courte)
    line {
        x1: "16", y1: "16",
        x2: "16", y2: "8",
        stroke: "black",
        "stroke-width": "2",
        "stroke-linecap": "square", // Extrémités carrées
        class: "hour-hand"
    }
    // L'aiguille des minutes (longue)
    line {
        x1: "16", y1: "16",
        x2: "24", y2: "16",
        stroke: "black",
        "stroke-width": "2",
        "stroke-linecap": "square",
        class: "minute-hand"
    }
    // Le centre
    circle { cx: "16", cy: "16", r: "1", fill: "black" }
}
                            }
                            div { class: "xp-pulse", style: "display: none;",
                                div {} div {} div {}
                            }
                            div { class: "terminal-bar", style: "display: none;" }
                            div { class: "dos-spin", style: "display: none;" }
                        }
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