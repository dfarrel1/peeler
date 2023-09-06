import os
from scapy.utils import rdpcap
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP

# Get the location of the script
script_dir = os.path.dirname(os.path.realpath(__file__))
# Construct the path for output.pcapng
output_file_path = os.path.join(script_dir, "loading", "scrubbed_RES_capture.pcapng")

# Load the pcapng file
packets = rdpcap(output_file_path)

shakespeare_text = """T"""

# Iterate over each packet and print its data
for idx, packet in enumerate(packets):
    decoded_data = None  # Initialize decoded_data to None at the beginning of each loop

    if packet.haslayer(Raw):
        data = packet[Raw].load
        
        try:
            # Try decoding the data
            decoded_data = data.decode()
            try:
                assert """T""" in decoded_data
                print(f"Packet {idx + 1} has been properly scrubbed.")
            except AssertionError:
                print(decoded_data)
        except UnicodeDecodeError:
            pass

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if decoded_data:
                # If data isn't the expected Shakespearean, raise an alert
                if "T" not in decoded_data:
                    print(f"Packet {idx + 1} might not have been properly scrubbed. It contains: {decoded_data[:50]}...")  # print first 50 chars for brevity
            else:
                print(f"Packet {idx + 1} (TCP/UDP) contains non-UTF8 data with length {len(data)} bytes. Scrubbing might have failed for this packet.")
        elif packet.haslayer(IP):
            packet_type = packet[IP].proto
            print(f"Packet {idx + 1} is of type {packet_type} with length {len(data)} bytes.")
        else:
            print(f"Packet {idx + 1} does not have an IP layer (length {len(data)} bytes). It might be an ARP or another type of packet.")
