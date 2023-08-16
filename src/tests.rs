#[cfg(test)]
mod unittests {
    use crate::lib::create_test_packet::create_test_tcp_packet;
    use crate::lib::create_test_packet::create_test_udp_packet;
    use crate::lib::gettcp::extract_tcp_fields;
    use crate::lib::getudp::extract_udp_fields;
    use libc::timeval;
    use pcap::PacketHeader;
    use pcap::{Capture, Packet};
    use std::{
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn test_extract_udp_fields_against_sample_file() {
        let current_file_path = Path::new(file!());
        let parent_directory = current_file_path
            .parent()
            .expect("Failed to get parent directory");
        let relative_path = parent_directory.join("../data/samples/udp_packet.pcap");
        let filepath_buf = relative_path
            .canonicalize()
            .expect("Failed to get canonical path");
        let filepath = filepath_buf.to_str().expect("Path is not valid UTF-8");
        let mut cap = Capture::from_file(filepath).unwrap();
        let packet = cap.next_packet().unwrap();
        let packet = Packet::new(packet.header, packet.data);

        // Call the function under test
        let result = extract_udp_fields(packet.clone());

        // Handle the Result
        match result {
            Ok(udp_fields) => {
                // Print the JSON representation
                let udp_header_json = serde_json::to_string_pretty(&udp_fields).unwrap();
                println!("udp_header_json: {}", udp_header_json);

                // Add assert statements to compare actual fields to expected values
                assert_eq!(udp_fields["src_port"].as_u64().unwrap(), 12345);
                assert_eq!(udp_fields["dst_port"].as_u64().unwrap(), 80);
                assert_eq!(udp_fields["len"].as_u64().unwrap(), 8);
                assert_eq!(udp_fields["checksum"].as_u64().unwrap(), 19457);
            }
            Err(err) => {
                // Print an error message
                println!("Error extracting UDP header fields: {}", err);

                // You can assert here that you were not expecting an error
                panic!("Test failed due to unexpected error: {}", err);
            }
        }
    }

    #[test]
    fn test_extract_udp_fields_from_generated_packet() {
        let packet_data = create_test_udp_packet();

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let ts_sec = timestamp.as_secs() as i64;
        let ts_usec = timestamp.subsec_micros() as i32;

        // Create a PacketHeader struct
        let header = PacketHeader {
            ts: timeval {
                tv_sec: ts_sec,
                tv_usec: ts_usec,
            },
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };

        // Create a TestPacket struct with the PacketHeader and a reference to the packet data
        let test_packet = Packet::new(&header, &packet_data);

        // Call the function under test
        let result = extract_udp_fields(test_packet);

        // Handle the Result
        match result {
            Ok(udp_fields) => {
                // Add assert statements to compare actual fields to expected values
                assert_eq!(udp_fields["src_port"].as_u64().unwrap(), 12345);
                assert_eq!(udp_fields["dst_port"].as_u64().unwrap(), 80);
                assert_eq!(udp_fields["len"].as_u64().unwrap(), 8);
                // Add your expected checksum value
                assert_eq!(udp_fields["checksum"].as_u64().unwrap(), 53528);
            }
            Err(err) => {
                // Print an error message
                println!("Error extracting UDP header fields: {}", err);
                // You can assert here that you were not expecting an error
                panic!("Test failed due to unexpected error: {}", err);
            }
        }
    }

    #[test]
    fn test_extract_tcp_fields_against_sample_file() {
        let current_file_path = Path::new(file!());
        let parent_directory = current_file_path
            .parent()
            .expect("Failed to get parent directory");
        let relative_path = parent_directory.join("../data/samples/tcp_packet.pcap");
        let filepath_buf = relative_path
            .canonicalize()
            .expect("Failed to get canonical path");
        let filepath = filepath_buf.to_str().expect("Path is not valid UTF-8");
        let mut cap = Capture::from_file(filepath).unwrap();
        let packet = cap.next_packet().unwrap();
        let packet = Packet::new(packet.header, packet.data);

        // Call the function under test
        let result = extract_tcp_fields(packet.clone());

        // Handle the Result
        match result {
            Ok(tcp_fields) => {
                // Add assert statements to compare actual fields to expected values
                assert_eq!(tcp_fields["src_port"].as_u64().unwrap() as u16, 12345);
                assert_eq!(tcp_fields["dst_port"].as_u64().unwrap() as u16, 80);
                assert_eq!(tcp_fields["seq_num"].as_u64().unwrap() as u32, 0);
                assert_eq!(tcp_fields["ack_num"].as_u64().unwrap() as u32, 0);
                // Add your expected checksum and other values
            }
            Err(err) => {
                // Print an error message
                println!("Error extracting TCP header fields: {}", err);
                // You can assert here that you were not expecting an error
                panic!("Test failed due to unexpected error: {}", err);
            }
        }
    }

    #[test]
    fn test_extract_tcp_fields() {
        // these test packets manually defined are failing the test
        // ERROR: Err(Custom { kind: InvalidData, error: "TCP data offset exceeds packet data length. packet.data.len(): 58, tcp_data_offset: 74" })
        // let packet_data: &[u8] = &[
        //     // Ethernet header (14 bytes)
        //     0x00, 0x16, 0x3e, 0x2f, 0xe4, 0x49, 0x00, 0x0c, 0x29, 0x7c, 0x6b, 0x6b, 0x08, 0x00,
        //     // IP header (20 bytes)
        //     0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x80, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x08, 0xc0, 0xa8, 0x00, 0x01,
        //     // TCP header (20 bytes)
        //     0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0xd0, 0x1f, 0x0a, 0x00, 0x00,
        //     // TCP payload (for example, 4 bytes)
        //     0x01, 0x02, 0x03, 0x04
        // ];

        let packet_data = create_test_tcp_packet();

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let ts_sec = timestamp.as_secs() as i64;
        let ts_usec = timestamp.subsec_micros() as i32;

        // Create a PacketHeader struct
        let header = PacketHeader {
            ts: timeval {
                tv_sec: ts_sec,
                tv_usec: ts_usec,
            },
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };

        // Create a TestPacket struct with the PacketHeader and a reference to the packet data
        let test_packet = Packet::new(&header, &packet_data);
        // let test_packet = get_test_tcp_packet();
        // let packet = test_packet.to_packet();
        let result = extract_tcp_fields(test_packet);

        // Check the result (example)
        println!("(test_extract_tcp_fields) result: {:?}", result);
        assert!(result.is_ok());
        let fields = result.unwrap();

        // Add assertions for each field based on the expected values
        assert_eq!(fields["src_port"].as_u64().unwrap() as u16, 49187);
        assert_eq!(fields["dst_port"].as_u64().unwrap() as u16, 80);
        assert_eq!(fields["seq_num"].as_u64().unwrap() as u32, 287454020);
        assert_eq!(fields["ack_num"].as_u64().unwrap() as u32, 1432778632);
        assert_eq!(fields["window_size"].as_u64().unwrap() as u16, 229);
        // assert_eq!(fields["checksum"].as_u64().unwrap() as u16, 0);
        assert_eq!(fields["urg_ptr"].as_u64().unwrap() as u16, 0);

        // Check flags
        let flags = fields["flags"].as_object().unwrap();
        assert_eq!(flags["fin"], false);
        assert_eq!(flags["syn"], false);
        assert_eq!(flags["rst"], false);
        assert_eq!(flags["psh"], false);
        assert_eq!(flags["ack"], true);
        assert_eq!(flags["urg"], false);
        assert_eq!(flags["ece"], false);
        assert_eq!(flags["cwr"], false);
    }
}
