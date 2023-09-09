#[cfg(test)]
mod unittests {
    use crate::lib::getipfields::extract_ethernet_ip_fields;
    use crate::lib::getpcapheader::extract_pcap_header_info;
    use crate::lib::gettcp::{extract_tcp_fields, is_tcp_packet};
    use crate::lib::getudp::{extract_udp_fields, is_udp_packet};
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
            let ip_header_json = match extract_ethernet_ip_fields(&packet) {
                Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                Err(err) => format!("Error extracting IP header fields: {}", err),
            };

            // Check if the packet is a TCP packet
            if is_tcp_packet(&packet) {
                let tcp_header_json = match extract_tcp_fields(&packet, ) {
                    Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                    Err(err) => format!("Error extracting TCP header fields: {}", err),
                };
                println!("tcp_header_json: {}", tcp_header_json);
            } else {
                println!("Not a TCP packet");
            }

            // Check if the packet is a UDP packet
            if is_udp_packet(&packet) {
                let udp_header_json = match extract_udp_fields(&packet) {
                    Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                    Err(err) => format!("Error extracting UDP header fields: {}", err),
                };
                println!("udp_header_json: {}", udp_header_json);
            } else {
                println!("Not a UDP packet");
            }

            println!("ip_header_json: {}", ip_header_json);
            println!("packet_header_json: {}", packet_header_json);
        }

        Ok(())
    }
}
