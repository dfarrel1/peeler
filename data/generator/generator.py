import os
from scapy.all import Ether, IP, UDP, TCP, wrpcap, conf

# Disable verbosity in scapy
conf.verb = 0

# Get the directory containing the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define packet layers for UDP
eth_layer_udp = Ether(src="00:01:02:03:04:05", dst="06:07:08:09:0A:0B")
ip_layer_udp = IP(src="192.168.1.1", dst="192.168.1.2")
udp_layer = UDP(sport=12345, dport=80)

# Construct the UDP packet
udp_packet = eth_layer_udp/ip_layer_udp/udp_layer

# Save the UDP packet to a pcap file
udp_pcap_path = os.path.join(script_dir, "../samples/udp_packet.pcap")
wrpcap(udp_pcap_path, udp_packet)

# Define packet layers for TCP
eth_layer_tcp = Ether(src="00:01:02:03:04:05", dst="06:07:08:09:0A:0B")
ip_layer_tcp = IP(src="192.168.1.1", dst="192.168.1.2")
tcp_layer = TCP(sport=12345, dport=80)

# Construct the TCP packet
tcp_packet = eth_layer_tcp/ip_layer_tcp/tcp_layer

# Save the TCP packet to a pcap file
tcp_pcap_path = os.path.join(script_dir, "../samples/tcp_packet.pcap")
wrpcap(tcp_pcap_path, tcp_packet)

print(f"UDP packet saved to {udp_pcap_path}")
print(f"TCP packet saved to {tcp_pcap_path}")
