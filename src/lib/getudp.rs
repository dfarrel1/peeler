use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::Engine as _;
use etherparse::UdpHeader;
use serde_json::{json, Value};
use std::error::Error;

pub fn extract_udp_fields(udp_header: &UdpHeader, payload: &[u8]) -> Result<Value, Box<dyn Error>> {
    let src_port = udp_header.source_port;
    let dst_port = udp_header.destination_port;
    let udp_len = udp_header.length;
    let checksum = udp_header.checksum;
    let udp_data_encoded = BASE64.encode(payload); // Encode the udp_data to Base64

    let udp_fields = json!({
        "src_port": src_port,
        "dst_port": dst_port,
        "len": udp_len,
        "checksum": checksum,
        "data": payload,
        "data_encoded": udp_data_encoded  // Add the new field
    });

    Ok(udp_fields)
}
