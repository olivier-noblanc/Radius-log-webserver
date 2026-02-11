use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename = "Event")]
pub struct RadiusEvent {
    #[serde(rename = "Timestamp")]
    pub timestamp: Option<String>,
    #[serde(rename = "Packet-Type")]
    pub packet_type: Option<String>,
    #[serde(rename = "Class")]
    pub class: Option<String>,
    #[serde(rename = "Acct-Session-Id")]
    pub acct_session_id: Option<String>,
    #[serde(rename = "Computer-Name")]
    pub server: Option<String>,
    
    // FIX: Added NAS-IP-Address to capture AP IP when Client-IP-Address is missing
    #[serde(rename = "Client-IP-Address")]
    pub ap_ip: Option<String>,
    #[serde(rename = "NAS-IP-Address")]
    pub nas_ip: Option<String>,

    #[serde(rename = "NAS-Identifier")]
    pub ap_name: Option<String>,
    #[serde(rename = "Client-Friendly-Name")]
    pub client_friendly_name: Option<String>,
    #[serde(rename = "Calling-Station-Id")]
    pub mac: Option<String>,
    #[serde(rename = "User-Name")]
    pub user_name: Option<String>,
    #[serde(rename = "SAM-Account-Name")]
    pub sam_account: Option<String>,
    #[serde(rename = "Reason-Code")]
    pub reason_code: Option<String>,

    // FIX: Catch-all for unexpected text content preventing crashes
    #[serde(rename = "$text", default)]
    pub _text: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RadiusRequest {
    pub timestamp: String,
    pub req_type: String,
    pub server: String,
    pub ap_ip: String,
    pub ap_name: String,
    pub mac: String,
    pub user: String,
    pub resp_type: String,
    pub reason: String,
    pub class_id: String,
    pub session_id: String,
    pub bg_color_class: Option<String>,
}
