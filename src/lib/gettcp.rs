use serde_json::{json, Value};
use std::error::Error;
// use etherparse::{TcpHeader, TcpHeaderSlice};
use base64::encode;
use etherparse::TcpHeader;

pub fn extract_tcp_fields(tcp_header: &TcpHeader, payload: &[u8]) -> Result<Value, Box<dyn Error>> {
    let src_port = tcp_header.source_port;
    let dst_port = tcp_header.destination_port;
    let seq_num = tcp_header.sequence_number;
    let ack_num = tcp_header.acknowledgment_number;
    let window_size = tcp_header.window_size;
    let checksum = tcp_header.checksum;
    let urg_ptr = tcp_header.urgent_pointer;

    let ns = tcp_header.ns;
    let cwr = tcp_header.cwr;
    let ece = tcp_header.ece;
    let urg = tcp_header.urg;
    let ack = tcp_header.ack;
    let psh = tcp_header.psh;
    let rst = tcp_header.rst;
    let syn = tcp_header.syn;
    let fin = tcp_header.fin;

    let tcp_data_encoded = encode(payload); // Encode the tcp_data to Base64

    let tcp_fields = json!({
        "src_port": src_port,
        "dst_port": dst_port,
        "seq_num": seq_num,
        "ack_num": ack_num,
        "window_size": tcp_header.window_size,
        "checksum": checksum,
        "urg_ptr": urg_ptr,
        "flags": {
            "ns": ns,
            "cwr": cwr,
            "ece": ece,
            "urg": urg,
            "ack": ack,
            "psh": psh,
            "rst": rst,
            "syn": syn,
            "fin": fin,
        },
        "data": payload,
        "data_encoded": tcp_data_encoded
    });

    Ok(tcp_fields)
}
