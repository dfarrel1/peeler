use serde_json::{json, Value};
use std::error::Error;
// use etherparse::{TcpHeader, TcpHeaderSlice};
use base64::encode;
use etherparse::TcpHeader;

pub fn extract_tcp_fields(tcp_header: &TcpHeader, payload: &[u8]) -> Result<Value, Box<dyn Error>> {
    let tcp_data_encoded = encode(payload); // Encode the tcp_data to Base64

    let tcp_fields = json!({
        "src_port": tcp_header.source_port,
        "dst_port": tcp_header.destination_port,
        "seq_num": tcp_header.sequence_number,
        "ack_num": tcp_header.acknowledgment_number,
        "window_size": tcp_header.window_size,
        "checksum": tcp_header.checksum,
        "urg_ptr": tcp_header.urgent_pointer,
        "flags": {
            "ns": tcp_header.ns,
            "cwr": tcp_header.cwr,
            "ece": tcp_header.ece,
            "urg": tcp_header.urg,
            "ack": tcp_header.ack,
            "psh": tcp_header.psh,
            "rst": tcp_header.rst,
            "syn": tcp_header.syn,
            "fin": tcp_header.fin,
        },
        "data": payload,
        "data_encoded": tcp_data_encoded
    });

    Ok(tcp_fields)
}
