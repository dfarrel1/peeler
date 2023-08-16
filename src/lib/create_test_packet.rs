use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use std::net::Ipv4Addr;

pub fn create_test_tcp_packet() -> [u8; 100] {
    let mut packet = [0u8; 100];

    let mut eth_packet = MutableEthernetPacket::new(&mut packet[..]).unwrap();
    eth_packet.set_destination(MacAddr::new(0, 0, 0, 0, 0, 0));
    eth_packet.set_source(MacAddr::new(0, 0, 0, 0, 0, 0));
    eth_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ip_packet = MutableIpv4Packet::new(eth_packet.payload_mut()).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(86);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(Ipv4Addr::new(127, 0, 0, 1));
    ip_packet.set_destination(Ipv4Addr::new(127, 0, 0, 1));
    let source_ip = ip_packet.get_source();
    let dest_ip = ip_packet.get_destination();

    let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
    tcp_packet.set_source(49187);
    tcp_packet.set_destination(80);
    tcp_packet.set_sequence(287454020);
    tcp_packet.set_acknowledgement(1432778632);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_window(229);
    tcp_packet.set_checksum(pnet::packet::tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &source_ip,
        &dest_ip,
    ));
    let mut flags = tcp_packet.get_flags();
    flags &= !pnet::packet::tcp::TcpFlags::SYN;
    flags |= pnet::packet::tcp::TcpFlags::ACK;
    tcp_packet.set_flags(flags);
    packet
}

pub fn create_test_udp_packet() -> [u8; 100] {
    let mut packet = [0u8; 100];

    let mut eth_packet = MutableEthernetPacket::new(&mut packet[..]).unwrap();
    eth_packet.set_destination(MacAddr::new(0, 0, 0, 0, 0, 0));
    eth_packet.set_source(MacAddr::new(0, 0, 0, 0, 0, 0));
    eth_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ip_packet = MutableIpv4Packet::new(eth_packet.payload_mut()).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(86);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_packet.set_source(Ipv4Addr::new(127, 0, 0, 1));
    ip_packet.set_destination(Ipv4Addr::new(127, 0, 0, 1));
    let source_ip = ip_packet.get_source();
    let dest_ip = ip_packet.get_destination();

    let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).unwrap();
    udp_packet.set_source(12345);
    udp_packet.set_destination(80);
    udp_packet.set_length(8); // Minimum length for UDP: header without data
    udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &source_ip,
        &dest_ip,
    ));

    packet
}
