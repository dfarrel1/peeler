use etherparse::Ethernet2HeaderSlice;
use pcap::Packet;

// it would seem that this function is working when used with getudp.rs
// but it does not seem to work in conjunction with gettcp.rs
pub fn extract_offset_and_ipheader(packet: Packet) -> Result<(usize, &[u8]), Box<dyn std::error::Error>> {
    let ethernet = Ethernet2HeaderSlice::from_slice(&packet.data[0..14]).unwrap();
    // Parse Ethernet header manually
    let ether_type = u16::from_be_bytes([packet.data[12], packet.data[13]]);
    println!("manually parsed ether type: {:?}", ether_type);

    // Check for VLAN tag (EtherType 0x8100-0x8FFF)
    let mut offset = ethernet.to_header().header_len();
    let ether_type = ethernet.ether_type();
    println!("ether_type: {:?}", ether_type);
    if (0x8100..=0x8FFF).contains(&ether_type) {
        offset += 4; // skip over VLAN tag
        let mut vlan_found = false;
        let mut tpid: u16 = 0;
        let mut tci: u16 = 0;
        let mut idx = ethernet.to_header().header_len();
        while idx + 4 < packet.data.len() {
            tpid = u16::from_be_bytes([packet.data[idx], packet.data[idx + 1]]);
            tci = u16::from_be_bytes([packet.data[idx + 2], packet.data[idx + 3]]);
            if tpid > 0x8FFF {
                break;
            }
            idx += 4;
            vlan_found = true;
        }

        if !vlan_found {
            println!("unsupported EtherType: {:?}", ether_type);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported EtherType",
            )));
        }
        println!("VLAN tag: tpid={}, tci={}", tpid, tci);
    }

    let ip_header_len = match ether_type {
        0x0800 => 20, // IPv4
        0x86DD => 40, // IPv6
        0x86F7 => 20, // IPv4 over IPsec
        0x8100 => 20, // IPv4 over VLAN
        _ => {
            println!("unsupported EtherType: {:?}", ether_type);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported EtherType",
            )))
        }
    };

    let ip_header = &packet.data[offset..offset + ip_header_len];
    Ok((offset, ip_header))
}