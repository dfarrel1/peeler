#[cfg(test)]
mod unittests {
    use crate::lib::getipfields::extract_ethernet_ip_fields;
    use crate::lib::getpcapheader::extract_pcap_header_info;
    use crate::lib::gettcp::extract_tcp_fields;
    use crate::lib::getudp::extract_udp_fields;
    use etherparse::{PacketHeaders, TransportHeader};
    use pcap::Capture;
    use std::path::Path;

    extern crate chrono;

    #[test]
    fn test_process_pcapng_file() -> Result<(), Box<dyn std::error::Error>> {
        let current_file_path = Path::new(file!());
        let parent_directory = current_file_path
            .parent()
            .expect("Failed to get parent directory");
        let relative_path = parent_directory.join("../data/samples/scrubbed_RES_capture.pcapng");
        let filepath_buf = relative_path
            .canonicalize()
            .expect("Failed to get canonical path");
        let filepath = filepath_buf.to_str().expect("Path is not valid UTF-8");

        let mut cap = Capture::from_file(filepath)?;

        while let Ok(packet) = cap.next_packet() {
            let packet_header_struct = extract_pcap_header_info(&packet);
            let packet_header_json = serde_json::to_string_pretty(&packet_header_struct)?;

            let headers = PacketHeaders::from_ethernet_slice(&packet)?;
            let ip_header_json = match extract_ethernet_ip_fields(&headers) {
                Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                Err(err) => format!("Error extracting IP header fields: {}", err),
            };

            if let Some(transport_header) = headers.transport {
                match transport_header {
                    TransportHeader::Udp(udp_header) => {
                        println!("UDP packet!");
                        let udp_header_json = match extract_udp_fields(&udp_header, headers.payload)
                        {
                            Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                            Err(err) => format!("Error extracting UDP header fields: {}", err),
                        };
                        println!("udp_header_json: {}", udp_header_json);
                    }
                    TransportHeader::Tcp(tcp_header) => {
                        println!("TCP packet!");
                        let tcp_header_json = match extract_tcp_fields(&tcp_header, headers.payload)
                        {
                            Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                            Err(err) => format!("Error extracting TCP header fields: {}", err),
                        };
                        println!("tcp_header_json: {}", tcp_header_json);
                    }
                    TransportHeader::Icmpv4(_) => {
                        println!("Found an ICMP v4 packet...");
                    }
                    TransportHeader::Icmpv6(_) => {
                        println!("Found an ICMP v6 packet...");
                    }
                }
            }

            println!("ip_header_json: {}", ip_header_json);
            println!("packet_header_json: {}", packet_header_json);
        }

        Ok(())
    }
}
