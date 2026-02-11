use dioxus::prelude::*;

#[component]
pub fn Footer() -> Element {
    rsx! {
        footer { class: "app-footer sr-only",
            p { "© 2026 RADIUS LOG CORE. Enterprise System." }
        }
    }
}

#[component]
pub fn GlobalLoader() -> Element {
    rsx! {
        div { 
            id: "global-loader", 
            class: "loader-overlay", 
            role: "progressbar", 
            "aria-busy": "true", 
            "aria-label": "System Initializing",
            div { class: "loader-progress-bar" }
            div { class: "loader-box",
                div { id: "loader-icon", class: "loader-icon",
                    div { class: "neon-ring" }
                    div { class: "dsfr-spinner" }
                    div { class: "terminal-bar" }
                    div { class: "xp-pulse",
                        div {} div {} div {}
                    }
                    div { class: "win31-hourglass", "⏳" }
                    div { class: "dos-spin" }
                    div { class: "macos-watch" }
                }
                div { class: "loader-text",
                    div { class: "loader-title", "SYSTEM BOOT" }
                    div { class: "loader-sub", "INITIALIZING..." }
                }
            }
        }
    }
}
