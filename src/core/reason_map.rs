use std::collections::HashMap;
use std::sync::OnceLock;

static REASON_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

pub fn get_reason_map() -> &'static HashMap<String, String> {
    REASON_MAP.get_or_init(|| {
        let json_content = include_str!("../reason_codes.json");
        serde_json::from_str(json_content).unwrap_or_default()
    })
}

pub fn map_reason(code: &str) -> String {
    let reason = get_reason_map()
        .get(code)
        .cloned()
        .unwrap_or_else(|| format!("Code {}", code));

    if code != "0" {
        format!("{} ({})", reason, code)
    } else {
        reason
    }
}

pub fn map_packet_type(code: &str) -> String {
    match code {
        "1" => "Access-Request".to_string(),
        "2" => "Access-Accept".to_string(),
        "3" => "Access-Reject".to_string(),
        "4" => "Accounting-Request".to_string(),
        "5" => "Accounting-Response".to_string(),
        "11" => "Access-Challenge".to_string(),
        _ => format!("Type {}", code),
    }
}
