// src/lib.rs
pub mod lib {
    pub mod create_test_packet;
    pub mod getipfields;
    pub mod getpcapheader;
    pub mod getprotocol;
    pub mod gettcp;
    pub mod getudp;
}

#[cfg(test)]
pub use lib::create_test_packet::create_test_tcp_packet;
#[cfg(test)]
pub use lib::create_test_packet::create_test_udp_packet;

pub use lib::getipfields::{extract_ethernet_ip_fields, extract_ipv4_fields, extract_ipv6_fields};
pub use lib::getpcapheader::extract_pcap_header_info;
pub use lib::getprotocol::get_protocol_from_ip_header;
pub use lib::gettcp::extract_tcp_fields;
pub use lib::getudp::extract_udp_fields;

mod smoketest;
mod testfactory;
mod tests;
