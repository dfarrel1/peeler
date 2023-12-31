#[cfg(test)]
mod unittests {
    use crate::lib::create_test_packet::create_test_tcp_packet;
    use crate::lib::create_test_packet::create_test_udp_packet;
    use crate::lib::gettcp::extract_tcp_fields;
    use crate::lib::getudp::extract_udp_fields;
    use libc::timeval;
    use pcap::PacketHeader;
    use pcap::{Capture, Packet};
    use std::path::Path;
    extern crate chrono;
    use chrono::prelude::*;
    use etherparse::{PacketHeaders, TransportHeader};

    #[test]
    fn test_extract_udp_fields_against_sample_file() {
        let data_path = match std::env::var("TEST_DATA_PATH") {
            Ok(env_path) => {
                println!("Using data path from environment variable: {}", env_path);
                env_path
            }
            Err(_) => {
                // If the environment variable is not found, fall back to the local path search
                let current_file_path = Path::new(file!());
                let parent_directory = current_file_path
                    .parent()
                    .expect("Failed to get parent directory");
                let relative_path = parent_directory.join("../data/samples/");
                let relative_path_buf = relative_path
                    .canonicalize()
                    .expect("Failed to get canonical path");
                let relative_path_str =
                    relative_path_buf.to_str().expect("Path is not valid UTF-8");
                println!("relative_path_str: {}", relative_path_str);

                relative_path_str.to_string()
            }
        };

        println!("data_path: {}", data_path);

        let filepath = Path::new(&data_path).join("udp_packet.pcap");
        println!("filepath: {}", filepath.display());

        let mut cap = Capture::from_file(filepath).unwrap();
        let packet = cap.next_packet().unwrap();
        let packet = Packet::new(packet.header, packet.data);

        let headers = PacketHeaders::from_ethernet_slice(&packet).unwrap();

        // Call the function under test
        let result = match headers
            .transport
            .ok_or("Cannot parse transport header")
            .unwrap()
        {
            TransportHeader::Udp(udp_header) => extract_udp_fields(&udp_header, headers.payload),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Not a UDP packet",
            ))
            .into()),
        };

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
        let now = Utc::now();
        let secs = now.timestamp();
        let micros = now.timestamp_micros() as i32;
        // let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let ts = timeval {
            tv_sec: secs,
            #[cfg(target_arch = "aarch64")]
            tv_usec: micros,
            #[cfg(not(target_arch = "aarch64"))]
            tv_usec: micros as i64,
        };

        let header = PacketHeader {
            ts,
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };

        // Create a TestPacket struct with the PacketHeader and a reference to the packet data
        let test_packet = Packet::new(&header, &packet_data);

        let headers = PacketHeaders::from_ethernet_slice(&test_packet).unwrap();

        // Call the function under test
        let result = match headers
            .transport
            .ok_or("Cannot parse transport header")
            .unwrap()
        {
            TransportHeader::Udp(udp_header) => extract_udp_fields(&udp_header, headers.payload),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Not a UDP packet",
            ))
            .into()),
        };

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

        let headers = PacketHeaders::from_ethernet_slice(&packet).unwrap();

        let result = match headers
            .transport
            .ok_or("Cannot parse transport header")
            .unwrap()
        {
            TransportHeader::Tcp(tcp_header) => extract_tcp_fields(&tcp_header, headers.payload),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Not a TCP packet",
            ))
            .into()),
        };

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
        let packet_data = create_test_tcp_packet();
        let now = Utc::now();
        let secs = now.timestamp();
        let micros = now.timestamp_micros() as i32;
        let ts = timeval {
            tv_sec: secs,
            #[cfg(target_arch = "aarch64")]
            tv_usec: micros,
            #[cfg(not(target_arch = "aarch64"))]
            tv_usec: micros as i64,
        };

        // Create a PacketHeader struct
        let header = PacketHeader {
            ts,
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };

        let packet = Packet::new(&header, &packet_data);

        let headers = PacketHeaders::from_ethernet_slice(&packet).unwrap();

        let result = match headers
            .transport
            .ok_or("Cannot parse transport header")
            .unwrap()
        {
            TransportHeader::Tcp(tcp_header) => extract_tcp_fields(&tcp_header, headers.payload),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Not a TCP packet",
            ))
            .into()),
        };

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
