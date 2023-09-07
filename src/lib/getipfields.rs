use crate::extract_offset_and_ipheader;
use etherparse::{Ipv4Header, Ipv4HeaderSlice, Ipv6Header, Ipv6HeaderSlice};
use pcap::Packet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryInto;

#[derive(Serialize, Deserialize)]
pub struct Ipv4Fields {
    pub caplen: u16,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
}

pub fn extract_ipv4_fields(header: &Ipv4Header) -> Ipv4Fields {
    Ipv4Fields {
        caplen: header.identification,
        protocol: header.protocol,
        header_checksum: header.header_checksum,
        source: header.source,
        destination: header.destination,
        source_mac: None,
        destination_mac: None,
    }
}

#[derive(Serialize, Deserialize)]
pub struct Ipv6Fields {
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
}

pub fn extract_ipv6_fields(header: &Ipv6Header) -> Ipv6Fields {
    Ipv6Fields {
        source: header.source,
        destination: header.destination,
        source_mac: None,
        destination_mac: None,
    }
}

pub fn extract_ethernet_ip_fields(packet: &Packet) -> Result<Value, Box<dyn std::error::Error>> {
    // Parse Ethernet header manually
    let dst_mac = &packet.data[0..6];
    let src_mac = &packet.data[6..12];
    let dst_mac_array: [u8; 6] = dst_mac.try_into()?;
    let src_mac_array: [u8; 6] = src_mac.try_into()?;
    let ether_type = u16::from_be_bytes([packet.data[12], packet.data[13]]);
    println!("manually parsed ether type: {:?}", ether_type);

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
            fields.destination_mac = Some(dst_mac_array);
            fields.source_mac = Some(src_mac_array);
            serde_json::to_value(&fields)?
        }
        0x86DD => {
            // IPv6
            let ipv6_header = Ipv6HeaderSlice::from_slice(ip_header)?;
            let mut fields = extract_ipv6_fields(&ipv6_header.to_header());
            fields.destination_mac = Some(dst_mac_array);
            fields.source_mac = Some(src_mac_array);
            serde_json::to_value(&fields)?
        }
        0x86F7 => {
            // IPv4 over IPsec
            let ipv4_header = Ipv4HeaderSlice::from_slice(ip_header)?;
            let mut fields = extract_ipv4_fields(&ipv4_header.to_header());
            fields.destination_mac = Some(dst_mac_array);
            fields.source_mac = Some(src_mac_array);
            serde_json::to_value(&fields)?
        }
        0x8100 => {
            // IPv4 over VLAN
            let ipv4_header = Ipv4HeaderSlice::from_slice(ip_header)?;
            let mut fields = extract_ipv4_fields(&ipv4_header.to_header());
            fields.destination_mac = Some(dst_mac_array);
            fields.source_mac = Some(src_mac_array);
            serde_json::to_value(&fields)?
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
