use bare::lib::getipfields::extract_ethernet_ip_fields;
use bare::lib::getpcapheader::extract_pcap_header_info;
use bare::lib::gettcp::{extract_tcp_fields, is_tcp_packet};
use bare::lib::getudp::{extract_udp_fields, is_udp_packet};
use pcap::Capture;
use std::path::Path;

mod testfactory;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let current_file_path = Path::new(file!());
    let parent_directory = current_file_path
        .parent()
        .expect("Failed to get parent directory");
    let relative_path = parent_directory.join("../data/samples/tcp_packet.pcap");
    // let relative_path = parent_directory.join("../data/samples/udp_packet.pcap");
    let filepath_buf = relative_path
        .canonicalize()
        .expect("Failed to get canonical path");
    let filepath = filepath_buf.to_str().expect("Path is not valid UTF-8");
    let mut cap = Capture::from_file(filepath)?;
    let mut i = 0;
    while let Ok(packet) = cap.next_packet() {
        i += 1;
        if i > 1 {
            break;
        }
        println!("i: {:?}", i);

        let packet_header_json = extract_pcap_header_info(&packet);
        let ip_header_json = match extract_ethernet_ip_fields(&packet) {
            Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
            Err(err) => format!("Error extracting IP header fields: {}", err),
        };
        println!("ip_header_json: {}", ip_header_json);

        // check if the packet is a TCP packet
        if !is_tcp_packet(&packet) {
            println!("Not a TCP packet");
        } else {
            println!("TCP packet");
            // get extract_tcp_header_values just like ip_header_json
            let tcp_header_json = match extract_tcp_fields(&packet) {
                Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                Err(err) => format!("Error extracting TCP header fields: {}", err),
            };
            println!("tcp_header_json: {}", tcp_header_json);
        };

        // check if the packet is a UDP packet
        if !is_udp_packet(&packet) {
            println!("Not a UDP packet");
        } else {
            println!("UDP packet");
            // get extract_udp_header_values just like ip_header_json
            let udp_header_json = match extract_udp_fields(&packet) {
                Ok(fields) => serde_json::to_string_pretty(&fields).unwrap(),
                Err(err) => format!("Error extracting UDP header fields: {}", err),
            };
            println!("udp_header_json: {}", udp_header_json);
        };

        let json_obj: serde_json::Value = serde_json::from_str(&packet_header_json)?;
        let packet_header_json = serde_json::to_string_pretty(&json_obj)?;
        println!("packet_header_json: {}", packet_header_json);
    }

    Ok(())
}
