// use std::time::{SystemTime, UNIX_EPOCH};
// use pcap::{PacketHeader,Packet};
// use libc::{timeval};

// // Define a wrapper struct
// pub struct TestPacket {
//     pub header: PacketHeader,
//     pub data: &'static [u8],
// }

// impl TestPacket {
//     pub fn to_packet(&self) -> Packet {
//         let header = self.header.clone();
//         Packet::new(&header, self.data)
//     }
// }

// // Function to create and return a test packet
// pub fn get_test_tcp_packet() -> Packet<'static> {
//     // Create a byte array containing a TCP packet
//     let packet_data: &[u8] = &[
//         // Ethernet header (14 bytes)
//         0x02, 0x42, 0xac, 0x11, 0x00, 0x02, 0x02, 0x42, 0xac, 0x11, 0x00, 0x01, 0x08, 0x00,
//         // IP header (20 bytes)
//         0x45, 0x00, 0x00, 0x34, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x11, 0x00, 0x01, 0xac, 0x11, 0x00, 0x02,
//         // TCP header (20 bytes)
//         0xc0, 0x23, 0x00, 0x50, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x80, 0x10, 0x00, 0xe5, 0x00, 0x00, 0x00, 0x00,
//     ];

//     let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
//     let ts_sec = timestamp.as_secs() as i64;
//     let ts_usec = timestamp.subsec_micros() as i32;

//     // Create a PacketHeader struct
//     let header = PacketHeader {
//         ts: timeval { tv_sec: ts_sec, tv_usec: ts_usec },
//         caplen: packet_data.len() as u32,
//         len: packet_data.len() as u32,
//     };

//     // Create a TestPacket struct with the PacketHeader and a reference to the packet data
//     Packet::new(&header, packet_data)

//     // {
//     //     header: header.clone(),
//     //     data: packet_data.clone(),
//     // }
// }
