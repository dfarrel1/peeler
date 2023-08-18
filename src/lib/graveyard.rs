// no longer in use
use std::time::{SystemTime, UNIX_EPOCH};
use libc::{timeval, suseconds_t};
    use pcap::{Packet, PacketHeader};

fn get_packet_header(packet_data: Packet) -> PacketHeader {
    // Get current time in seconds and microseconds
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let ts_sec = timestamp.as_secs() as i64;
    let ts_usec = timestamp.subsec_micros() as i32;

    // Set caplen and len to length of the packet
    let caplen = packet_data.len() as u32;
    let len = caplen;

    PacketHeader {
        ts: timeval { tv_sec: ts_sec, tv_usec: ts_usec },
        caplen,
        len,
    }
}