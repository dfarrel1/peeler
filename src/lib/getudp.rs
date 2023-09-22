use base64::encode;
use etherparse::UdpHeader;
use serde_json::{json, Value};
use std::error::Error;

// on sample packet
// 0000   ff ff ff ff ff ff 02 53 4c 56 91 f6 81 00 00 32
// 0010   08 00 45 10 00 3a af 88 40 00 40 11 a0 fb ac 14
// 0020   91 f6 ac 14 ff ff 02 bb 02 bb 00 26 23 c5 41 00
// 0030   25 89 00 00 00 00 91 f6 91 f6 04 ea 04 01 91 fd
// 0040   35 00 91 fd 30 f3 04 01 91 f6 39 00
// we should find
// The IP header starts at byte 18 (0x12).
// The IP header length is 20 bytes.
// The protocol field (at byte 23) is 0x11, which indicates UDP.
// The UDP header starts at byte 42 (0x2A).
// we should find:
// Source port: bytes 42 and 43 (0x2A and 0x2B) are 0x02 and 0xBB, which in decimal is 699.
// Destination port: bytes 44 and 45 (0x2C and 0x2D) are 0x02 and 0xBB, which in decimal is 699.
// Length: bytes 46 and 47 (0x2E and 0x2F) are 0x00 and 0x26, which in decimal is 38.
// Checksum: bytes 48 and 49 (0x30 and 0x31) are 0x23 and 0xC5, which in decimal is 9165.
// Parse packet
// output should look like ({
//     "src_port": 699,
//     "dst_port": 699,
//     "len": 38,
//     "checksum": 9165
//   })

pub fn extract_udp_fields(udp_header: &UdpHeader, payload: &[u8]) -> Result<Value, Box<dyn Error>> {
    let src_port = udp_header.source_port;
    let dst_port = udp_header.destination_port;
    let udp_len = udp_header.length;
    let checksum = udp_header.checksum;
    let udp_data_encoded = encode(payload); // Encode the udp_data to Base64

    let udp_fields = json!({
        "src_port": src_port,
        "dst_port": dst_port,
        "len": udp_len,
        "checksum": checksum,
        "data": payload,
        "data_encoded": udp_data_encoded  // Add the new field
    });

    println!("udp_fields: {udp_fields}");

    Ok(udp_fields)
}
