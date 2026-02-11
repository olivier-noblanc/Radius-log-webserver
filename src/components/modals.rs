use dioxus::prelude::*;
// use crate::core::models::RadiusRequest;

#[component]
pub fn SecurityModal() -> Element {
    rsx! {
        div { id: "securityModal", class: "modal-overlay",
            a { href: "#", class: "close-overlay" }
            div { class: "modal-content glass-panel p-6 max-w-md w-full animate-pop",
                h2 { class: "text-xl font-bold mb-4", "SECURITY LOCK" }
                p { class: "mb-6 opacity-80", "Access restricted. Verify identity to unlock control center." }
                a { href: "/api/login", class: "btn-lock w-full", "VALIDATE IDENTITY" }
            }
        }
    }
}

#[component]
pub fn DetailModal() -> Element {
    rsx! {
        div { id: "detailModal", class: "modal-overlay",
            a { href: "#", class: "close-overlay" }
            div {
                class: "modal-content glass-panel p-0 max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden animate-pop",
                div { class: "p-4 border-b border-white/10 flex justify-between items-center bg-black/20",
                    h3 { class: "text-sm font-bold tracking-widest uppercase", "LOG ENTRY DETAILS" }
                    a { href: "#", class: "btn-modal-close", "×" }
                }
                div { id: "modalBody", class: "p-6 overflow-y-auto custom-scrollbar" }
            }
        }
    }
}
