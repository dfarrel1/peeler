import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap
from itertools import cycle

# Excerpt from Shakespeare's Hamlet
shakespeare_text = """T"""
# Convert Shakespeare text to bytes
shakespeare_bytes = shakespeare_text.encode()
# Create an iterator to cycle through Shakespeare bytes
shakespeare_cycle = cycle(shakespeare_bytes)

def replace_with_shakespeare(packet):
    # Check if the packet has a Raw payload (i.e., data)
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        if packet.haslayer(Raw):
            # Get the length of the data part
            data_len = len(packet[Raw].load)
            # Replace with Shakespeare text of the same length
            packet[Raw].load = bytes([next(shakespeare_cycle) for _ in range(data_len)])
            print(f"Replaced {data_len} bytes of data with Shakespeare text.")
    return packet

# Get the location of the script
script_dir = os.path.dirname(os.path.realpath(__file__))
# Construct the path for RES_capture.pcapng
input_file_path = os.path.join(script_dir, "loading", "RES_capture.pcapng")
# Construct the path for the output file
output_file_path = os.path.join(script_dir, "samples", "scrubbed_RES_capture.pcapng")

# Read the pcapng file
packets = rdpcap(input_file_path)

# Replace data in packets with Shakespeare text
new_packets = [replace_with_shakespeare(packet) for packet in packets]

# Write the modified packets to a new pcapng file
wrpcap(output_file_path, new_packets)
