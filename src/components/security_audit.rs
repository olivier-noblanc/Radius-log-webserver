use dioxus::prelude::*;
use crate::infrastructure::security_audit::{SecurityAuditReport, SecurityVulnerability};

#[derive(Props, Clone, PartialEq)]
pub struct SecurityAuditProps {
    pub report: SecurityAuditReport,
}

#[component]
pub fn SecurityAudit(props: SecurityAuditProps) -> Element {
    let critical_count = props.report.vulnerabilities.iter().filter(|v| v.severity == "CRITICAL").count();
    let high_count = props.report.vulnerabilities.iter().filter(|v| v.severity == "HIGH").count();
    let medium_count = props.report.vulnerabilities.iter().filter(|v| v.severity == "MEDIUM").count();
    
    rsx! {
        div { class: "security-audit-container p-6",
            
            // Header avec statut global
            div { class: "mb-8 text-center",
                h1 { class: "text-3xl font-bold mb-2", "SECURITY AUDIT REPORT" }
                div { class: "text-xs text-muted uppercase tracking-widest", "Generated: {props.report.timestamp}" }
                
                if critical_count > 0 || high_count > 0 {
                    div { class: "mt-4 p-4 bg-red-500/10 border-l-4 border-red-500",
                        div { class: "text-xl font-bold text-fail", "⚠️ CRITICAL ISSUES DETECTED" }
                        div { class: "text-sm mt-2", 
                            "{critical_count} Critical, {high_count} High, {medium_count} Medium severity issues"
                        }
                    }
                } else {
                    div { class: "mt-4 p-4 bg-green-500/10 border-l-4 border-green-500",
                        div { class: "text-xl font-bold text-success", "✅ NO CRITICAL ISSUES" }
                        div { class: "text-sm mt-2", "System security baseline met" }
                    }
                }
            }

            // Vulnerabilities Section
            if !props.report.vulnerabilities.is_empty() {
                div { class: "mb-8",
                    h2 { class: "text-xl font-bold mb-4 flex items-center gap-2",
                        "🔴 Vulnerabilities"
                        span { class: "text-sm font-normal opacity-50", "({props.report.vulnerabilities.len()} found)" }
                    }
                    
                    div { class: "space-y-3",
                        for vuln in &props.report.vulnerabilities {
                            VulnerabilityCard { vulnerability: vuln.clone() }
                        }
                    }
                }
            }

            // Certificates Section
            div { class: "mb-8",
                h2 { class: "text-xl font-bold mb-4 flex items-center gap-2",
                    "📜 Windows Certificate Store"
                    span { class: "text-sm font-normal opacity-50", "(LOCAL_MACHINE\\MY)" }
                }
                
                if props.report.certificates.is_empty() {
                    div { class: "glass-panel p-6 text-center border-dashed border-2 border-muted/30",
                        div { class: "text-2xl mb-2", "🔍" }
                        div { class: "text-sm font-bold text-muted", "No certificates found in LOCAL_MACHINE\\MY" }
                        div { class: "text-xxs text-muted mt-1", "This is normal if no machine-wide SSL/RADIUS certificates have been installed." }
                    }
                } else {
                    div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                        for cert in &props.report.certificates {
                            div { 
                                class: format!(
                                    "glass-panel p-4 {}",
                                    if cert.is_expired { "border-l-4 border-red-500" } 
                                    else if cert.days_until_expiration < 30 { "border-l-4 border-yellow-500" }
                                    else { "" }
                                ),
                                
                                div { class: "font-bold text-sm mb-2", "{cert.subject}" }
                                div { class: "text-xxs text-muted space-y-1",
                                    div { "Issuer: {cert.issuer}" }
                                    div { "Expires: {cert.valid_to}" }
                                    div { 
                                        class: if cert.is_expired { "text-fail font-bold" } 
                                               else if cert.days_until_expiration < 30 { "text-yellow-500 font-bold" }
                                               else { "text-success" },
                                        if cert.is_expired {
                                            "❌ EXPIRED"
                                        } else if cert.days_until_expiration < 30 {
                                            "⚠️ Expires in {cert.days_until_expiration} days"
                                        } else {
                                            "✅ Valid ({cert.days_until_expiration} days remaining)"
                                        }
                                    }
                                    if cert.is_self_signed {
                                        div { class: "text-yellow-500", "⚠️ Self-Signed" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // TLS Configuration
            div { class: "mb-8",
                h2 { class: "text-xl font-bold mb-4", "🔐 TLS/SSL Configuration" }
                
                div { class: "glass-panel p-4",
                    div { class: "grid grid-cols-2 md:grid-cols-5 gap-4 mb-4",
                        ProtocolBadge { name: "SSL 3.0", enabled: props.report.tls_config.ssl_3_0_enabled, critical: true }
                        ProtocolBadge { name: "TLS 1.0", enabled: props.report.tls_config.tls_1_0_enabled, critical: false }
                        ProtocolBadge { name: "TLS 1.1", enabled: props.report.tls_config.tls_1_1_enabled, critical: false }
                        ProtocolBadge { name: "TLS 1.2", enabled: props.report.tls_config.tls_1_2_enabled, critical: false }
                        ProtocolBadge { name: "TLS 1.3", enabled: props.report.tls_config.tls_1_3_enabled, critical: false }
                    }
                    
                    if !props.report.tls_config.weak_ciphers_detected.is_empty() {
                        div { class: "mt-4 p-3 bg-red-500/10 border-l-4 border-red-500",
                            div { class: "font-bold text-fail mb-2", "⚠️ Weak Ciphers Detected" }
                            div { class: "text-xxs space-y-1",
                                for cipher in &props.report.tls_config.weak_ciphers_detected {
                                    div { "• {cipher}" }
                                }
                            }
                        }
                    }

                    // Cipher Suite Order (GPO/Priority)
                    div { class: "mt-6",
                        h3 { class: "text-sm font-bold mb-3 opacity-80 uppercase tracking-widest", "Cipher Suite Negotiation Order" }
                        div { class: "glass-panel p-0 bg-black/20 overflow-hidden",
                            if props.report.tls_config.cipher_suites.is_empty() {
                                div { class: "p-4 text-xs text-muted italic", 
                                    "Managed by Windows Defaults (No GPO override detected)" 
                                }
                            } else {
                                div { class: "divide-y divide-white/5",
                                    for (i, cipher) in props.report.tls_config.cipher_suites.iter().enumerate() {
                                        div { class: "p-2 px-4 text-xxs font-mono flex items-center gap-3 hover:bg-white/5",
                                            span { class: "opacity-30 w-4", "{i+1}" }
                                            span { class: if props.report.tls_config.weak_ciphers_detected.contains(cipher) { "text-fail" } else { "text-primary/80" }, 
                                                "{cipher}" 
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Event Logs
            if !props.report.event_log_analysis.is_empty() {
                div { class: "mb-8",
                    h2 { class: "text-xl font-bold mb-4", "📋 Schannel Event Logs (24h)" }
                    
                    div { class: "glass-panel p-4 max-h-96 overflow-y-auto",
                        div { class: "text-xxs font-mono space-y-2",
                            for log in &props.report.event_log_analysis {
                                div { 
                                    class: if log.contains("Event ID") { "text-yellow-500" } else { "text-muted" },
                                    "{log}"
                                }
                            }
                        }
                    }
                }
            }

            // Recommendations
            if !props.report.recommendations.is_empty() {
                div { class: "mb-8",
                    h2 { class: "text-xl font-bold mb-4", "💡 Recommendations" }
                    
                    div { class: "glass-panel p-4",
                        ul { class: "text-sm space-y-2",
                            for rec in &props.report.recommendations {
                                li { class: "flex items-start gap-2",
                                    span { class: "text-primary", "▸" }
                                    span { "{rec}" }
                                }
                            }
                        }
                    }
                }
            }

            // Footer avec actions
            div { class: "flex gap-4 justify-center mt-8",
                a { 
                    href: "/api/debug", 
                    target: "_blank",
                    class: "btn-glass btn-primary",
                    "📥 DOWNLOAD JSON REPORT"
                }
                a { 
                    href: "/", 
                    class: "btn-glass",
                    "← BACK TO DASHBOARD"
                }
            }
        }
    }
}

#[component]
fn VulnerabilityCard(vulnerability: SecurityVulnerability) -> Element {
    let severity_color = match vulnerability.severity.as_str() {
        "CRITICAL" => "border-red-500 bg-red-500/5",
        "HIGH" => "border-orange-500 bg-orange-500/5",
        "MEDIUM" => "border-yellow-500 bg-yellow-500/5",
        _ => "border-blue-500 bg-blue-500/5",
    };
    
    let severity_emoji = match vulnerability.severity.as_str() {
        "CRITICAL" => "🔴",
        "HIGH" => "🟠",
        "MEDIUM" => "🟡",
        _ => "🔵",
    };
    
    rsx! {
        div { class: "glass-panel p-4 border-l-4 {severity_color}",
            div { class: "flex items-start justify-between mb-2",
                div { class: "font-bold text-sm", "{severity_emoji} {vulnerability.title}" }
                div { 
                    class: format!("text-xxs px-2 py-1 rounded {}", 
                        match vulnerability.severity.as_str() {
                            "CRITICAL" => "bg-red-500 text-white",
                            "HIGH" => "bg-orange-500 text-white",
                            "MEDIUM" => "bg-yellow-500 text-black",
                            _ => "bg-blue-500 text-white",
                        }
                    ),
                    "{vulnerability.severity}"
                }
            }
            
            div { class: "text-xs text-muted mb-2", "{vulnerability.description}" }
            
            if let Some(cve) = &vulnerability.cve {
                div { class: "text-xxs",
                    a { 
                        href: "https://nvd.nist.gov/vuln/detail/{cve}",
                        target: "_blank",
                        class: "text-primary underline",
                        "📌 {cve}"
                    }
                }
            }
        }
    }
}

#[component]
fn ProtocolBadge(name: String, enabled: bool, critical: bool) -> Element {
    let status_class = if enabled {
        if critical { "bg-red-500/20 border-red-500 text-fail" }
        else { "bg-green-500/20 border-green-500 text-success" }
    } else {
        "bg-gray-500/20 border-gray-500 text-muted"
    };
    
    let icon = if enabled {
        if critical { "❌" } else { "✅" }
    } else {
        "⚫"
    };
    
    rsx! {
        div { class: "text-center p-3 border-2 rounded {status_class}",
            div { class: "text-2xl mb-1", "{icon}" }
            div { class: "text-xxs font-bold", "{name}" }
            div { class: "text-xxs mt-1 opacity-70", if enabled { "ENABLED" } else { "DISABLED" } }
        }
    }
}
