use dioxus::prelude::*;

// On ajoute une propriété pour savoir si l'utilisateur est connecté
#[component]
pub fn SecurityModal(is_authorized: bool) -> Element {
    rsx! {
        div { id: "securityModal", class: "modal-overlay",
            a { href: "#", class: "close-overlay" }
            div { class: "modal-content glass-panel p-6 max-w-md w-full animate-pop",

                // LOGIQUE CONDITIONNELLE
                if is_authorized {
                    // CAS 1 : Utilisateur connecté -> Afficher l'audit (ou un lien)
                    h2 { class: "text-xl font-bold mb-4", "SECURITY STATUS" }
                    div { class: "mb-4 text-center",
                        div { class: "text-4xl mb-2", "🔓" }
                        p { class: "opacity-80", "Identity Verified. Access Granted." }
                    }
                    a {
                        href: "/security-audit",
                        class: "btn-glass btn-primary w-full text-center",
                        "🔍 VIEW FULL SECURITY AUDIT"
                    }
                } else {
                    // CAS 2 : Utilisateur non connecté -> Afficher le login
                    h2 { class: "text-xl font-bold mb-4", "SECURITY LOCK" }
                    p { class: "mb-6 opacity-80", "Access restricted. Verify identity to unlock control center." }
                    a { href: "/api/login", class: "btn-lock w-full", "VALIDATE IDENTITY" }
                }
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
