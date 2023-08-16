use pcap::{Packet};
use serde_json::json;

pub fn extract_pcap_header_info(packet: Packet) -> String {
    let packet = Packet::new(packet.header, packet.data);     
    

    json!({
        "caplen": packet.header.caplen,
        "origlen": packet.header.len,
        "ts_sec": packet.header.ts.tv_sec,
        "ts_usec": packet.header.ts.tv_usec
    }).to_string()
}