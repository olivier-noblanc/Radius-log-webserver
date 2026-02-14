use crate::infrastructure::security_audit::{SecurityAuditReport, SecurityVulnerability};
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct SecurityAuditProps {
    pub report: SecurityAuditReport,
}

#[component]
pub fn SecurityAudit(props: SecurityAuditProps) -> Element {
    let (vulnerabilities, maintenance_alarms): (Vec<_>, Vec<_>) = props
        .report
        .vulnerabilities
        .iter()
        .partition(|v| !v.is_maintenance_alarm);

    let critical_count = vulnerabilities
        .iter()
        .filter(|v| v.severity == "CRITICAL")
        .count();
    let high_count = vulnerabilities
        .iter()
        .filter(|v| v.severity == "HIGH")
        .count();
    let medium_count = vulnerabilities
        .iter()
        .filter(|v| v.severity == "MEDIUM")
        .count();

    rsx! {
        div { class: "security-audit-container p-6",

            // Header avec statut global
            div { class: "mb-8 text-center",
                h1 { class: "text-3xl font-bold mb-2", {rust_i18n::t!("security_audit.title").to_string()} }
                div { class: "text-xs text-muted uppercase tracking-widest", "{rust_i18n::t!(\"security_audit.generated\").to_string()}: {props.report.timestamp}" }

                if critical_count > 0 || high_count > 0 {
                    div { class: "mt-4 p-4 bg-red-500/10 border-l-4 border-red-500",
                        div { class: "text-xl font-bold text-fail", "⚠️ {rust_i18n::t!(\"security_audit.critical_issues\").to_string()}" }
                        div { class: "text-sm mt-2",
                            {rust_i18n::t!("security_audit.issues_count", critical = critical_count, high = high_count, medium = medium_count).to_string()}
                        }
                    }
                } else {
                    div { class: "mt-4 p-4 bg-green-500/10 border-l-4 border-green-500",
                        div { class: "text-xl font-bold text-success", "✅ {rust_i18n::t!(\"security_audit.no_critical_issues\").to_string()}" }
                        div { class: "text-sm mt-2", {rust_i18n::t!("security_audit.system_baseline_met").to_string()} }
                    }
                }
            }

            // Vulnerabilities Section
            if !vulnerabilities.is_empty() {
                div { class: "mb-8",
                    h2 { class: "text-xl font-bold mb-4 flex items-center gap-2",
                        "🔴 {rust_i18n::t!(\"security_audit.vulnerabilities\").to_string()}"
                        span { class: "text-sm font-normal opacity-50",
                            "({rust_i18n::t!(\"security_audit.found\", count = vulnerabilities.len()).to_string()})"
                        }
                    }

                    div { class: "space-y-3",
                        for vuln in vulnerabilities {
                            VulnerabilityCard { vulnerability: vuln.clone() }
                        }
                    }
                }
            }

            // Maintenance Alarms Section (API/System errors that need dev attention)
            if !maintenance_alarms.is_empty() {
                div { class: "mb-8",
                    h2 { class: "text-xl font-bold mb-4 flex items-center gap-2 text-blue-400",
                        "🛠️ {rust_i18n::t!(\"security_audit.maintenance_alarms\").to_string()}"
                        span { class: "text-sm font-normal opacity-50 text-muted",
                            "({rust_i18n::t!(\"security_audit.required_action\").to_string()})"
                        }
                    }

                    div { class: "space-y-3",
                        for alarm in maintenance_alarms {
                            VulnerabilityCard { vulnerability: alarm.clone() }
                        }
                    }
                }
            }

            // Certificates Section
            div { class: "mb-8",
                h2 { class: "text-xl font-bold mb-4 flex items-center gap-2",
                    "📜 {rust_i18n::t!(\"security_audit.windows_cert_store\")}"
                }

                div { class: "space-y-8",
                    // 1. Personal Certificates
                    div {
                        h3 { class: "text-lg font-bold mb-3 opacity-80", "👤 {rust_i18n::t!(\"security_audit.personal_my\").to_string()}" }
                        if props.report.certificates.is_empty() {
                            div { class: "glass-panel p-4 text-xs text-muted italic", {rust_i18n::t!("security_audit.no_personal_certs").to_string()} }
                        } else {
                            {render_cert_grid(&props.report.certificates)}
                        }
                    }

                    // 2. Intermediate Authorities
                    div {
                        h3 { class: "text-lg font-bold mb-3 opacity-80", "🏢 {rust_i18n::t!(\"security_audit.intermediate_ca\").to_string()}" }
                        if props.report.intermediate_certificates.is_empty() {
                            div { class: "glass-panel p-4 text-xs text-muted italic", {rust_i18n::t!("security_audit.no_intermediate_certs").to_string()} }
                        } else {
                            {render_cert_grid(&props.report.intermediate_certificates)}
                        }
                    }

                    // 3. Root Authorities
                    div {
                        h3 { class: "text-lg font-bold mb-3 opacity-80", "🏛️ {rust_i18n::t!(\"security_audit.root_authorities\").to_string()}" }
                        if props.report.ca_certificates.is_empty() {
                            div { class: "glass-panel p-4 text-xs text-muted italic", {rust_i18n::t!("security_audit.no_root_certs").to_string()} }
                        } else {
                            {render_cert_grid(&props.report.ca_certificates)}
                        }
                    }

                    // 4. Trusted Publishers
                    div {
                        h3 { class: "text-lg font-bold mb-3 opacity-80", "✍️ {rust_i18n::t!(\"security_audit.trusted_publishers\").to_string()}" }
                        if props.report.trusted_publishers.is_empty() {
                            div { class: "glass-panel p-4 text-xs text-muted italic", {rust_i18n::t!("security_audit.no_trusted_publishers").to_string()} }
                        } else {
                            {render_cert_grid(&props.report.trusted_publishers)}
                        }
                    }

                    // 5. Disallowed Certificates
                    if !props.report.disallowed_certificates.is_empty() {
                        div {
                            h3 { class: "text-lg font-bold mb-3 text-fail", "🚫 {rust_i18n::t!(\"security_audit.disallowed_certs\").to_string()}" }
                            {render_cert_grid(&props.report.disallowed_certificates)}
                        }
                    }

                    // 6. Admin Toolbox (Hints & Documentation)
                    div { class: "mt-8 border-t border-border pt-6",
                        h2 { class: "text-xl font-bold mb-4 flex items-center gap-2",
                            span { "🧰" }
                            {rust_i18n::t!("security_audit.admin_toolbox").to_string()}
                        }

                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-6",
                            // Certificate Renewal
                            div { class: "glass-panel p-4 border-l-4 border-blue-500",
                                h4 { class: "font-bold text-blue-400 mb-2 flex items-center gap-2",
                                    span { "🔄" }
                                    {rust_i18n::t!("security_audit.cert_renewal").to_string()}
                                }
                                div { class: "text-xxs space-y-2 opacity-90",
                                    p { {rust_i18n::t!("security_audit.cert_renewal_desc").to_string()} }
                                    div { class: "space-y-2",
                                        div {
                                            p { class: "mb-1 font-bold text-xxs opacity-70", "• CMD (certutil):" }
                                            div { class: "bg-black/40 p-2 rounded font-mono text-success break-all",
                                                "certutil -importpfx -f -p \"password\" \"path\\to\\cert.pfx\""
                                            }
                                        }
                                        div {
                                            p { class: "mb-1 font-bold text-xxs opacity-70", "• PowerShell:" }
                                            div { class: "bg-black/40 p-2 rounded font-mono text-success break-all",
                                                "$pwd = ConvertTo-SecureString -String \"password\" -Force -AsPlainText; Import-PfxCertificate -FilePath \"path\\to\\cert.pfx\" -CertStoreLocation Cert:\\LocalMachine\\My -Password $pwd"
                                            }
                                        }
                                    }
                                    ul { class: "list-disc ml-4 space-y-1 mt-2",
                                        li { {rust_i18n::t!("security_audit.ksp_desc").to_string()} }
                                        li { {rust_i18n::t!("security_audit.csp_desc").to_string()} }
                                    }
                                }
                            }

                            // NTAuth Management
                            div { class: "glass-panel p-4 border-l-4 border-yellow-500",
                                h4 { class: "font-bold text-yellow-500 mb-2 flex items-center gap-2",
                                    span { "🏛️" }
                                    {rust_i18n::t!("security_audit.ntauth_mgmt").to_string()}
                                }
                                div { class: "text-xxs space-y-2 opacity-90",
                                    p { {rust_i18n::t!("security_audit.ntauth_missing").to_string()} }
                                    div { class: "space-y-3",
                                        div {
                                            p { class: "mb-1 font-bold", "• {rust_i18n::t!(\"security_audit.enterprise_wide\").to_string()}" }
                                            div { class: "space-y-1",
                                                p { class: "text-[9px] opacity-60", "CMD:" }
                                                div { class: "bg-black/40 p-1.5 rounded font-mono text-success break-all",
                                                    "certutil -dspublish -f \"CA_cert.cer\" NTAuthCA"
                                                }
                                            }
                                        }
                                        div {
                                            p { class: "mb-1 font-bold", "• {rust_i18n::t!(\"security_audit.local_machine_only\").to_string()}" }
                                            div { class: "space-y-2",
                                                div {
                                                    p { class: "text-[9px] opacity-60", "CMD:" }
                                                    div { class: "bg-black/40 p-1.5 rounded font-mono text-success break-all",
                                                        "certutil -addstore -f NTAuth \"CA_cert.cer\""
                                                    }
                                                }
                                                div {
                                                    p { class: "text-[9px] opacity-60", "PowerShell:" }
                                                    div { class: "bg-black/40 p-1.5 rounded font-mono text-success break-all",
                                                        "Import-Certificate -FilePath \"CA_cert.cer\" -CertStoreLocation Cert:\\LocalMachine\\NTAuth"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // TLS Configuration
            div { class: "mb-8",
                h2 { class: "text-xl font-bold mb-4", "🔐 {rust_i18n::t!(\"security_audit.tls_config\").to_string()}" }

                div { class: "glass-panel p-4",
                    div { class: "grid grid-cols-2 md:grid-cols-5 gap-4 mb-4",
                        ProtocolBadge { name: "SSL 3.0".to_string(), enabled: props.report.tls_config.ssl_3_0_enabled, critical: true }
                        ProtocolBadge { name: "TLS 1.0".to_string(), enabled: props.report.tls_config.tls_1_0_enabled, critical: false }
                        ProtocolBadge { name: "TLS 1.1".to_string(), enabled: props.report.tls_config.tls_1_1_enabled, critical: false }
                        ProtocolBadge { name: "TLS 1.2".to_string(), enabled: props.report.tls_config.tls_1_2_enabled, critical: false }
                        ProtocolBadge { name: "TLS 1.3".to_string(), enabled: props.report.tls_config.tls_1_3_enabled, critical: false }
                    }

                    if !props.report.tls_config.weak_ciphers_detected.is_empty() {
                        div { class: "mt-4 p-3 bg-red-500/10 border-l-4 border-red-500",
                            div { class: "font-bold text-fail mb-2", "⚠️ {rust_i18n::t!(\"security_audit.weak_ciphers\").to_string()}" }
                            div { class: "text-xxs space-y-1",
                                for cipher in &props.report.tls_config.weak_ciphers_detected {
                                    div { "• {cipher}" }
                                }
                            }
                        }
                    }

                    // Cipher Suite Order (GPO/Priority)
                    div { class: "mt-6",
                        h3 { class: "text-sm font-bold mb-3 opacity-80 uppercase tracking-widest", {rust_i18n::t!("security_audit.cipher_order").to_string()} }
                        div { class: "glass-panel p-0 bg-black/20 overflow-hidden",
                            if props.report.tls_config.cipher_suites.is_empty() {
                                div { class: "p-4 text-xs text-muted italic",
                                    {rust_i18n::t!("security_audit.managed_by_windows").to_string()}
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
                    h2 { class: "text-xl font-bold mb-4", "📋 {rust_i18n::t!(\"security_audit.event_logs\").to_string()}" }

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
                    h2 { class: "text-xl font-bold mb-4", "💡 {rust_i18n::t!(\"security_audit.recommendations\").to_string()}" }

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
                    {rust_i18n::t!("security_audit.download_json").to_string()}
                }
                a {
                    href: "/",
                    class: "btn-glass",
                    {rust_i18n::t!("security_audit.back_dashboard").to_string()}
                }
            }
        }
    }
}

#[component]
fn VulnerabilityCard(vulnerability: SecurityVulnerability) -> Element {
    let severity_color = if vulnerability.is_maintenance_alarm {
        "border-blue-500/50 bg-blue-500/5 shadow-inner shadow-blue-500/10"
    } else {
        match vulnerability.severity.as_str() {
            "CRITICAL" => "border-red-500 bg-red-500/5",
            "HIGH" => "border-orange-500 bg-orange-500/5",
            "MEDIUM" => "border-yellow-500 bg-yellow-500/5",
            _ => "border-blue-500 bg-blue-500/5",
        }
    };

    let severity_emoji = if vulnerability.is_maintenance_alarm {
        "🛠️"
    } else {
        match vulnerability.severity.as_str() {
            "CRITICAL" => "🔴",
            "HIGH" => "🟠",
            "MEDIUM" => "🟡",
            _ => "🔵",
        }
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
        if critical {
            "bg-red-500/20 border-red-500 text-fail"
        } else {
            "bg-green-500/20 border-green-500 text-success"
        }
    } else {
        "bg-gray-500/20 border-gray-500 text-muted"
    };

    let icon = if enabled {
        if critical {
            "❌"
        } else {
            "✅"
        }
    } else {
        "⚫"
    };

    rsx! {
        div { class: "text-center p-3 border-2 rounded {status_class}",
            div { class: "text-2xl mb-1", "{icon}" }
            div { class: "text-xxs font-bold", "{name}" }
            div { class: "text-xxs mt-1 opacity-70", {if enabled { rust_i18n::t!("security_audit.enabled").to_string() } else { rust_i18n::t!("security_audit.disabled").to_string() }} }
        }
    }
}

fn render_cert_grid(certs: &[crate::infrastructure::security_audit::CertificateInfo]) -> Element {
    rsx! {
        div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4",
            for cert in certs {
                div {
                    class: format!(
                        "glass-panel p-4 {}",
                        if cert.is_expired { "border-l-4 border-red-500" }
                        else if cert.days_until_expiration < 30 { "border-l-4 border-yellow-500" }
                        else { "" }
                    ),

                    div { class: "flex justify-between items-start mb-2",
                        div { class: "font-bold text-sm truncate pr-2", title: "{cert.subject}", "{cert.subject}" }
                        div { class: "flex gap-1 flex-shrink-0",
                            if cert.wpa3_ready {
                                span {
                                    class: "bg-purple-500/20 text-purple-400 text-[10px] px-1.5 py-0.5 rounded border border-purple-500/30 font-bold",
                                    "WPA3 READY"
                                }
                            }
                            if cert.in_ntauth {
                                span {
                                    class: "bg-blue-500/20 text-blue-400 text-[10px] px-1.5 py-0.5 rounded border border-blue-500/30 font-bold",
                                    "NTAuth"
                                }
                            } else if !cert.is_self_signed && !cert.subject.contains("Found Local Cert") {
                                span {
                                    class: "bg-yellow-500/20 text-yellow-500 text-[10px] px-1.5 py-0.5 rounded border border-yellow-500/30 font-bold",
                                    "NOT IN NTAUTH"
                                }
                            }
                        }
                    }

                    div { class: "text-xxs text-muted space-y-1",
                        div { class: "truncate", title: "{cert.issuer}", "{rust_i18n::t!(\"security_audit.issuer\").to_string()}: {cert.issuer}" }
                        div { "{rust_i18n::t!(\"security_audit.expires\").to_string()}: {cert.valid_to}" }
                        div { class: "flex items-center gap-2",
                            span { "{cert.algo} {cert.bits} bits" }
                            if cert.is_modern_ksp {
                                span { class: "text-success", {rust_i18n::t!("security_audit.ksp").to_string()} }
                            } else {
                                span { class: "text-yellow-500", {rust_i18n::t!("security_audit.legacy_csp").to_string()} }
                            }
                        }
                        div { class: "truncate opacity-60 italic", title: "{cert.provider}", "{rust_i18n::t!(\"security_audit.provider\").to_string()}: {cert.provider}" }
                        div {
                            class: if cert.is_expired { "text-fail font-bold" }
                                   else if cert.days_until_expiration < 30 { "text-yellow-500 font-bold" }
                                   else { "text-success" },
                            {if cert.is_expired {
                                rust_i18n::t!("security_audit.expired").to_string()
                            } else if cert.days_until_expiration < 30 {
                                rust_i18n::t!("security_audit.expires_in_days", days = cert.days_until_expiration).to_string()
                            } else {
                                rust_i18n::t!("security_audit.valid_days", days = cert.days_until_expiration).to_string()
                            }}
                        }
                        if cert.is_self_signed {
                            div { class: "text-yellow-500", "⚠️ {rust_i18n::t!(\"security_audit.self_signed\").to_string()}" }
                        }

                        if !cert.in_ntauth && !cert.is_self_signed && !cert.subject.contains("Found Local Cert") {
                            div { class: "mt-2 p-1.5 bg-yellow-500/5 border border-yellow-500/20 rounded",
                                div { class: "text-yellow-500 font-bold mb-1", "💡 {rust_i18n::t!(\"security_audit.resolution_hint\").to_string()}" }
                                div { class: "italic opacity-80", {rust_i18n::t!("security_audit.resolution_hint_text").to_string()} }
                            }
                        }
                    }
                }
            }
        }
    }
}
