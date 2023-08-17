use crate::extract_offset_and_ipheader;
use etherparse::{Ipv4Header, Ipv4HeaderSlice, Ipv6Header, Ipv6HeaderSlice};
use pcap::Packet;
use serde_json::{json, Value};

pub fn extract_ipv4_fields(header: &Ipv4Header) -> Value {
    json!({
        "identification": header.identification,
        "protocol": header.protocol,
        "header_checksum": header.header_checksum,
        "source": header.source,
        "destination": header.destination,
    })
}

pub fn extract_ipv6_fields(header: &Ipv6Header) -> Value {
    json!({
        "source": header.source,
        "destination": header.destination,
    })
}

pub fn extract_ethernet_ip_fields(packet: &Packet) -> Result<Value, Box<dyn std::error::Error>> {
    // Parse Ethernet header manually
    let dst_mac = &packet.data[0..6];
    let src_mac = &packet.data[6..12];
    let ether_type = u16::from_be_bytes([packet.data[12], packet.data[13]]);
    println!("manually parsed ether type: {:?}", ether_type);

    // let ip_header = &packet.data[offset..offset + ip_header_len];
    // try new technique
    let (_offset, ip_header) = match extract_offset_and_ipheader(packet) {
        Ok(header) => header,
        Err(e) => {
            println!("error: {:?}", e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported EtherType",
            )));
        }
    };

    // determine IP version and parse header fields accordingly
    let ip_version = match ether_type {
        0x0800 => {
            // IPv4
            let ipv4_header = Ipv4HeaderSlice::from_slice(ip_header)?;
            let mut fields = extract_ipv4_fields(&ipv4_header.to_header());
            // add dst_mac and src_mac to fields
            fields["dst_mac"] = json!(dst_mac);
            fields["src_mac"] = json!(src_mac);
            fields
        }
        0x86DD => {
            // IPv6
            let ipv6_header = Ipv6HeaderSlice::from_slice(ip_header)?;
            let mut fields = extract_ipv6_fields(&ipv6_header.to_header());
            fields["dst_mac"] = json!(dst_mac);
            fields["src_mac"] = json!(src_mac);
            fields
        }
        0x86F7 => {
            // IPv4 over IPsec
            let ipv4_header = Ipv4HeaderSlice::from_slice(ip_header)?;
            let mut fields = extract_ipv4_fields(&ipv4_header.to_header());
            fields["dst_mac"] = json!(dst_mac);
            fields["src_mac"] = json!(src_mac);
            fields
        }
        0x8100 => {
            // IPv4 over VLAN
            let ipv4_header = Ipv4HeaderSlice::from_slice(ip_header)?;
            let mut fields = extract_ipv4_fields(&ipv4_header.to_header());
            fields["dst_mac"] = json!(dst_mac);
            fields["src_mac"] = json!(src_mac);
            fields
        }
        _ => {
            println!("unsupported EtherType: {:?}", ether_type);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported EtherType",
            )));
        }
    };

    Ok(ip_version)
}
