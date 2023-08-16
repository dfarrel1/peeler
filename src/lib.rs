// src/lib.rs
pub mod lib {
    pub mod create_test_packet;
    pub mod getheader;
    pub mod getipfields;
    pub mod getpcapheader;
    pub mod getprotocol;
    pub mod gettcp;
    pub mod getudp;
}

pub use lib::create_test_packet::create_test_tcp_packet;
pub use lib::create_test_packet::create_test_udp_packet;
pub use lib::getheader::extract_offset_and_ipheader;
pub use lib::getipfields::{extract_ethernet_ip_fields, extract_ipv4_fields, extract_ipv6_fields};
pub use lib::getpcapheader::extract_pcap_header_info;
pub use lib::getprotocol::get_protocol_from_ip_header;
pub use lib::gettcp::{extract_tcp_fields, is_tcp_packet};
pub use lib::getudp::{extract_udp_fields, is_udp_packet};

mod testfactory;
mod tests;
