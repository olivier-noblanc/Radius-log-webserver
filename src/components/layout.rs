use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct LayoutProps {
    pub title: String,
    pub theme: String,
    pub build_version: String,
    pub git_sha: String,
    pub is_authorized: bool,
    pub children: Element,
    pub css_files: Vec<String>,
}

#[component]
pub fn Layout(props: LayoutProps) -> Element {
    let loader_class = format!("theme-{}", props.theme);
    
    rsx! {
        head {
            meta { charset: "utf-8" }
            meta { name: "viewport", content: "width=device-width, initial-scale=1" }
            title { "{props.title}" }
            
            // Base CSS (toujours chargé)
            link { rel: "stylesheet", href: "/css/style.css" }
            
            // Theme CSS (conditionnel)
            for css_file in &props.css_files {
                link { rel: "stylesheet", href: "{css_file}" }
            }
            
            script { src: "/js/htmx.min.js", defer: true }
            script { src: "/js/app.js", defer: true }
        }
        body { "data-theme": "{props.theme}",
            if !props.is_authorized {
                div { id: "human-gate", class: "gate-overlay",
                    div { class: "gate-content",
                        h1 { class: "gate-logo", "RADIUS // CORE" }
                        p { class: "gate-subtitle", "Authentication Required" }
                        a { 
                            href: "/api/login?theme={props.theme}", 
                            class: "btn-glass btn-primary mt-6", 
                            "AUTHORIZE ACCESS" 
                        }
                    }
                }
            } else {
                div { class: "app-wrapper",
                    crate::components::header::Header {
                        build_version: props.build_version.clone(),
                        theme: props.theme.clone()
                    }
                    
                    div { class: "container",
                        {props.children}
                    }
                    
                    div { id: "view-dashboard", style: "display: none;" }
                }
                
                // LOADER GLOBAL (HTMX-driven)
                div { 
                    id: "global-loader", 
                    class: "htmx-indicator",
                    
                    div { class: "loader-progress-bar" }
                    
                    div { class: "loader-box {loader_class}",
                        div { class: "loader-icon",
                            // Loader variant selon le thème
                            match props.theme.as_str() {
                                "xp" => rsx! { div { class: "xp-pulse", div {} div {} div {} } },
                                "dos" => rsx! { div { class: "dos-spin" } },
                                "win31" => rsx! { div { class: "win31-hourglass", "⌛" } },
                                "terminal" => rsx! { div { class: "terminal-bar" } },
                                "macos" => rsx! { div { class: "macos-watch" } },
                                _ => rsx! { div { class: "neon-ring" } }
                            }
                        }
                        div { class: "loader-text",
                            div { class: "loader-title", "PROCESSING" }
                            div { class: "loader-sub", "Please wait..." }
                        }
                    }
                }
                
                crate::components::modals::DetailModal {}
                crate::components::modals::SecurityModal {}
            }
        }
    }
}
