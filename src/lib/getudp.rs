use crate::extract_offset_and_ipheader;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use pcap::Packet;
use serde_json::{json, Value};
use std::error::Error;

pub fn is_udp_packet(packet: Packet) -> bool {
    // Parse Ethernet header
    let ether_type = u16::from_be_bytes([packet[12], packet[13]]);
    println!("checking against ether type {:?}", ether_type);
    println!("checking against ether type (hex) 0x{:02x}", ether_type);
    // check if ether_type is any of the following (2048, 37366, 33024) use integer notation, not hexadecimal
    if ether_type == 2048 || ether_type == 37366 || ether_type == 33024 {
        println!("found a UDP packet with ether type {:?}", ether_type);
    } else {
        return false;
    }
    println!("now trying the negative search using hexadecimal");
    if ether_type != 0x0800 && ether_type != 0x8100 && ether_type != 0x9196 {
        // Not IPv4 or non-standard EtherType
        println!(
            "ether type is not 0x0800 0x8100, or 0x9196, it is {:?}",
            ether_type
        );
    }

    let (_, ip_header) = extract_offset_and_ipheader(packet).unwrap();

    println!("ip_header {:?}", ip_header);

    let protocol: u8 = match ether_type {
        0x0800 => {
            // IPv4
            let ip_versioned_header = Ipv4HeaderSlice::from_slice(ip_header);
            ip_versioned_header.unwrap().protocol()
        }
        0x86DD => {
            // IPv6
            let ip_versioned_header = Ipv6HeaderSlice::from_slice(ip_header);
            ip_versioned_header.unwrap().next_header()
        }
        0x86F7 => {
            // IPv4 over IPsec
            let ip_versioned_header = Ipv4HeaderSlice::from_slice(ip_header);
            ip_versioned_header.unwrap().protocol()
        }
        0x8100 => {
            // IPv4 over VLAN
            let ip_versioned_header = Ipv4HeaderSlice::from_slice(ip_header);
            ip_versioned_header.unwrap().protocol()
        }
        _ => {
            println!("unsupported EtherType: {:?}", ether_type);
            return false;
        }
    };

    if protocol != 17 {
        // Not UDP
        println!("protocol is not 17, it is {:?}", protocol);
        return false;
    } else {
        println!("protocol is 17, it is {:?}", protocol);
    }

    // Packet is UDP
    true
}

// on sample packet
// 0000   ff ff ff ff ff ff 02 53 4c 56 91 f6 81 00 00 32
// 0010   08 00 45 10 00 3a af 88 40 00 40 11 a0 fb ac 14
// 0020   91 f6 ac 14 ff ff 02 bb 02 bb 00 26 23 c5 41 00
// 0030   25 89 00 00 00 00 91 f6 91 f6 04 ea 04 01 91 fd
// 0040   35 00 91 fd 30 f3 04 01 91 f6 39 00
// we should find
// The IP header starts at byte 18 (0x12).
// The IP header length is 20 bytes.
// The protocol field (at byte 23) is 0x11, which indicates UDP.
// The UDP header starts at byte 42 (0x2A).
// we should find:
// Source port: bytes 42 and 43 (0x2A and 0x2B) are 0x02 and 0xBB, which in decimal is 699.
// Destination port: bytes 44 and 45 (0x2C and 0x2D) are 0x02 and 0xBB, which in decimal is 699.
// Length: bytes 46 and 47 (0x2E and 0x2F) are 0x00 and 0x26, which in decimal is 38.
// Checksum: bytes 48 and 49 (0x30 and 0x31) are 0x23 and 0xC5, which in decimal is 9165.
// Parse packet
// output should look like ({
//     "src_port": 699,
//     "dst_port": 699,
//     "len": 38,
//     "checksum": 9165
//   })

pub fn extract_udp_fields(packet: Packet) -> Result<Value, Box<dyn Error>> {
    let (offset, ip_header) = extract_offset_and_ipheader(packet.clone()).unwrap();
    println!("offset: {:?}", offset);

    let ip_header_len = ip_header.len();
    println!("ip_header_len: {:?}", ip_header_len);

    let udp_header_offset = offset + ip_header_len;
    println!("udp_header_offset: {:?}", udp_header_offset);

    if udp_header_offset + 8 > packet.data.len() {
        return Err("Packet data is too short for UDP header".into());
    }

    let src_port = u16::from_be_bytes([
        packet.data[udp_header_offset],
        packet.data[udp_header_offset + 1],
    ]);
    let dst_port = u16::from_be_bytes([
        packet.data[udp_header_offset + 2],
        packet.data[udp_header_offset + 3],
    ]);
    let udp_len = u16::from_be_bytes([
        packet.data[udp_header_offset + 4],
        packet.data[udp_header_offset + 5],
    ]);
    let checksum = u16::from_be_bytes([
        packet.data[udp_header_offset + 6],
        packet.data[udp_header_offset + 7],
    ]);

    println!("src_port: {}", src_port);
    println!("dst_port: {}", dst_port);
    println!("udp_len: {}", udp_len);
    println!("checksum: {}", checksum);

    if udp_len < 8 {
        return Err("Invalid UDP length".into());
    }

    let udp_data_offset = udp_header_offset + 8; // UDP header is 8 bytes long
    let udp_data_len = (udp_len as usize)
        .checked_sub(8)
        .ok_or("UDP length underflow")?;

    if udp_data_offset + udp_data_len > packet.data.len() {
        return Err("Packet data is too short for UDP data".into());
    }

    let udp_data = packet.data[udp_data_offset..udp_data_offset + udp_data_len].to_vec(); // Extract data

    let udp_fields = json!({
        "src_port": src_port,
        "dst_port": dst_port,
        "len": udp_len,
        "checksum": checksum,
        "data": udp_data
    });

    println!("udp_fields: {}", udp_fields);

    Ok(udp_fields)
}
