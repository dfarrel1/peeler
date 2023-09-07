use pcap::Packet;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PcapHeaderInfo {
    pub caplen: u32,
    pub origlen: u32,
    pub ts_sec: i64,
    pub ts_usec: i64,
}

#[allow(clippy::all)] // we need the explicit type caste to address arm/x86 differences
pub fn extract_pcap_header_info(packet: &Packet) -> PcapHeaderInfo {
    PcapHeaderInfo {
        caplen: packet.header.caplen,
        origlen: packet.header.len,
        ts_sec: packet.header.ts.tv_sec,
        ts_usec: packet.header.ts.tv_usec as i64,
    }
}
