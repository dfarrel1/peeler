use crate::extract_offset_and_ipheader;
use pcap::Packet;
use serde_json::{json, Value};
use std::error::Error;
// use etherparse::{TcpHeader, TcpHeaderSlice};
use base64::encode;

pub fn is_tcp_packet(packet: &Packet) -> bool {
    // Extract the EtherType from the Ethernet header
    let ether_type = u16::from_be_bytes([packet.data[12], packet.data[13]]);
    if ether_type != 0x0800 {
        return false; // Not an IPv4 packet
    }

    // Extract the protocol from the IP header
    let protocol = packet.data[23];
    if protocol != 0x06 {
        return false; // Not a TCP packet
    }

    // Extract the TCP header length from the TCP header
    let tcp_header_len = ((packet.data[46] & 0xf) << 2) as usize;

    // Check if the packet is long enough to contain the TCP header
    if packet.data.len() < 14 + 20 + tcp_header_len {
        return false;
    }

    true
}

fn get_tcp_header_length(tcp_header: &[u8]) -> usize {
    let data_offset = tcp_header[12] >> 4; // extract the 'Data Offset' field
    (data_offset as usize) * 4 // convert to bytes
}

fn get_tcp_data_offset(ethernet_header: &[u8], ip_header: &[u8], tcp_header: &[u8]) -> usize {
    let ethernet_header_len = ethernet_header.len();
    let ip_header_len = (ip_header[0] & 0x0F) as usize * 4;
    let tcp_header_len = ((tcp_header[12] >> 4) as usize) * 4;
    ethernet_header_len + ip_header_len + tcp_header_len
}

pub fn extract_tcp_fields(packet: &Packet) -> Result<Value, Box<dyn Error>> {
    let (offset, ip_header) = extract_offset_and_ipheader(packet).unwrap();
    let ip_header_len = ip_header.len();
    let tcp_header_offset = offset + ip_header_len;

    // Ensure the indices used are within the range of the packet data
    if packet.data.len() <= tcp_header_offset + 19 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Packet data length ({}) is too short. It must be at least {} bytes to contain the Ethernet, IP, and TCP headers.",
                packet.data.len(),
                tcp_header_offset + 20
            )
        )));
    }

    let tcp_header = &packet[tcp_header_offset..tcp_header_offset + 20];
    let _tcp_header_len = get_tcp_header_length(tcp_header);
    let ethernet_header = &packet[0..14]; // Without VLAN tag
    let tcp_data_offset = get_tcp_data_offset(ethernet_header, ip_header, tcp_header);

    // Ensure the indices used are within the range of the packet data
    if packet.data.len() <= tcp_header_offset + 19 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TCP Header data is incomplete",
        )));
    }
    let src_port = u16::from_be_bytes([
        packet.data[tcp_header_offset],
        packet.data[tcp_header_offset + 1],
    ]);
    let dst_port = u16::from_be_bytes([
        packet.data[tcp_header_offset + 2],
        packet.data[tcp_header_offset + 3],
    ]);
    let seq_num = u32::from_be_bytes([
        packet.data[tcp_header_offset + 4],
        packet.data[tcp_header_offset + 5],
        packet.data[tcp_header_offset + 6],
        packet.data[tcp_header_offset + 7],
    ]);
    let ack_num = u32::from_be_bytes([
        packet.data[tcp_header_offset + 8],
        packet.data[tcp_header_offset + 9],
        packet.data[tcp_header_offset + 10],
        packet.data[tcp_header_offset + 11],
    ]);
    let data_offset_and_flags = u16::from_be_bytes([
        packet.data[tcp_header_offset + 12],
        packet.data[tcp_header_offset + 13],
    ]);
    let window_size = u16::from_be_bytes([
        packet.data[tcp_header_offset + 14],
        packet.data[tcp_header_offset + 15],
    ]);
    let checksum = u16::from_be_bytes([
        packet.data[tcp_header_offset + 16],
        packet.data[tcp_header_offset + 17],
    ]);
    let urg_ptr = u16::from_be_bytes([
        packet.data[tcp_header_offset + 18],
        packet.data[tcp_header_offset + 19],
    ]);

    let flags = data_offset_and_flags & 0x01FF;
    let ns = (flags & 0x0100) != 0;
    let cwr = (flags & 0x0080) != 0;
    let ece = (flags & 0x0040) != 0;
    let urg = (flags & 0x0020) != 0;
    let ack = (flags & 0x0010) != 0;
    let psh = (flags & 0x0008) != 0;
    let rst = (flags & 0x0004) != 0;
    let syn = (flags & 0x0002) != 0;
    let fin = (flags & 0x0001) != 0;

    // these are older attemtps
    // now defined above
    // TODO remove code
    // let tcp_header_len = ((packet.data[tcp_header_offset + 12] & 0xf0) >> 4) * 4; // TCP header length in bytes
    // let tcp_data_offset = tcp_header_offset + tcp_header_len as usize;

    // Make sure the data offset does not exceed the packet data length
    if packet.data.len() < tcp_data_offset {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "TCP data offset exceeds packet data length. packet.data.len(): {}, tcp_data_offset: {}",
                packet.data.len(),
                tcp_data_offset
            )
        )));
    }
    let tcp_data = packet.data[tcp_data_offset..].to_vec(); // The rest is TCP payload

    let tcp_data_encoded = encode(&tcp_data); // Encode the udp_data to Base64

    let tcp_fields = json!({
        "src_port": src_port,
        "dst_port": dst_port,
        "seq_num": seq_num,
        "ack_num": ack_num,
        "window_size": window_size,
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
        "data": tcp_data,
        "data_encoded": tcp_data_encoded
    });

    Ok(tcp_fields)
}
