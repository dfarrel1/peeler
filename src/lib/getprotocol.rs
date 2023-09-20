use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use std::error::Error;

pub fn get_protocol_from_ip_header(
    ip_header: &[u8],
    ether_type: u16,
) -> Result<u8, Box<dyn Error>> {
    match ether_type {
        0x0800 | 0x86F7 | 0x8100 => {
            let ip_versioned_header = Ipv4HeaderSlice::from_slice(ip_header)?;
            Ok(ip_versioned_header.protocol())
        }
        0x86DD => {
            let ip_versioned_header = Ipv6HeaderSlice::from_slice(ip_header)?;
            Ok(ip_versioned_header.next_header())
        }
        _ => {
            let ether_type_str = format!("Unsupported EtherType: {ether_type:?}");
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ether_type_str,
            )))
        }
    }
}
