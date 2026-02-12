use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct LayoutProps {
    pub title: String,
    pub theme: String,
    pub build_version: String,
    pub git_sha: String,
    pub is_authorized: bool,
    pub children: Element,
}

#[component]
pub fn Layout(props: LayoutProps) -> Element {
<<<<<<< Updated upstream
    // Déterminer quelle classe de loader afficher selon le thème
    let loader_class = match props.theme.as_str() {
        "dsfr" => "theme-dsfr",
        "xp" => "theme-xp",
        "win31" => "theme-win31",
        "win95" => "theme-win95",
        "dos" => "theme-dos",
        "terminal" => "theme-terminal",
        "neon" => "theme-neon",
        "cyber-tactical" => "theme-cyber-tactical",
        "onyx-glass" => "theme-onyx-glass",
        "macos" => "theme-macos",
        "amber" => "theme-amber",
        "c64" => "theme-c64",
        "win2000" => "theme-win2000",
        "compact" => "theme-compact",
        "aero" => "theme-aero",
        _ => "theme-neon",
    };

    let loader_icon = match props.theme.as_str() {
        "dsfr" => rsx! { div { class: "dsfr-spinner" } },
        "xp" => rsx! { 
            div { class: "xp-pulse",
                div {}
                div {}
                div {}
            }
        },
        "win31" => rsx! { div { class: "win31-hourglass", "⌛" } },
        "win95" => rsx! { div { class: "win31-hourglass", "⌛" } },
        "win2000" => rsx! { div { class: "win31-hourglass", "⌛" } },
        "dos" => rsx! { div { class: "dos-spin" } },
        "terminal" => rsx! { div { class: "terminal-bar" } },
        "macos" => rsx! { div { class: "macos-watch" } },
        _ => rsx! { div { class: "neon-ring" } },
    };

    rsx! {
        head {
            meta { charset: "utf-8" }
            meta { name: "viewport", content: "width=device-width, initial-scale=1.0" }
            title { "{props.title}" }
            
            // CSS de base (TOUJOURS chargé)
            link { rel: "stylesheet", href: "/css/style.css" }
            
            // Fonts locales (100% offline, pas de CDN)
            link { rel: "stylesheet", href: "/css/fonts.css" }
            
            // Mega-bundle thèmes (tous scopés par data-theme)
            link { rel: "stylesheet", href: "/api/themes.bundle.css" }
            
            // HTMX (Version locale pour conformité CSP)
            script { 
                src: "/js/htmx.min.js",
                defer: true
            }
            
            // App.js (notre code minimal)
            script { 
                src: "/js/app.js",
                defer: true
            }
        }
        
        body { 
            "data-theme": "{props.theme}",
            
            // LOADER GLOBAL (caché par défaut, affiché par HTMX)
            div { 
                id: "global-loader",
                class: "htmx-indicator",
                
                div { class: "loader-progress-bar" }
                
                div { 
                    class: "loader-box {loader_class}",
                    
                    div { class: "loader-icon",
                        {loader_icon}
                    }
                    
                    div { class: "loader-text",
                        div { class: "loader-title", "PROCESSING" }
                        div { class: "loader-sub", "Please wait..." }
                    }
                }
            }

            // GATE (si pas autorisé)
            if !props.is_authorized {
                div { id: "human-gate",
                    div { class: "gate-content",
                        h1 { 
                            class: "gate-logo glitch-text",
                            "data-text": "RADIUS // LOG",
                            "RADIUS // LOG"
                        }
                        div { class: "gate-subtitle", "Network Authentication System" }
                        div { class: "mt-6",
                            a { 
                                href: "/api/login?theme={props.theme}",
                                class: "btn-glass btn-primary",
                                "AUTHENTICATE"
                            }
                        }
                    }
                }
            }

            // APP ROOT
            div { 
                id: "app-root",
                class: if props.is_authorized { "visible" } else { "" },
                
                crate::components::header::Header {
                    build_version: props.build_version,
                    theme: props.theme.clone()
                }

                div { class: "container",
                    {props.children}
                }

=======
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
                
>>>>>>> Stashed changes
                crate::components::modals::DetailModal {}
                crate::components::modals::SecurityModal {}
            }
        }
    }
}

