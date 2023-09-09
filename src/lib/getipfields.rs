use etherparse::{IpHeader, Ipv4Header, Ipv6Header, PacketHeaders};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

pub fn extract_ethernet_ip_fields(headers: &PacketHeaders) -> Result<Value, Box<dyn std::error::Error>> {
    // we ensure to return Error if link header is not properly formatted
    // no more need for the conversion to arrays since they're already in the correct form
    let dst_mac = headers.link.as_ref().ok_or("Cannot parse link header")?.destination;
    let src_mac = headers.link.as_ref().ok_or("Cannot parse link header")?.source;

    let ip_header = headers.ip.as_ref().ok_or("Cannot parse ip header")?;
    // if you also need the offset you can access: headers.link?.header_len()

    // determine IP version and parse header fields accordingly
    let ip_version = match ip_header {
        IpHeader::Version4(v4_header, _) => {
                let mut fields = extract_ipv4_fields(&v4_header);
                fields.destination_mac = Some(dst_mac);
                fields.source_mac = Some(src_mac);
                serde_json::to_value(&fields)?
        }
        IpHeader::Version6(v6_header, _) => {
                let mut fields = extract_ipv6_fields(&v6_header);
                fields.destination_mac = Some(dst_mac);
                fields.source_mac = Some(src_mac);
                serde_json::to_value(&fields)?
        }
    };

    Ok(ip_version)
}
