# peeler

get all the parts from the packet that we want

## goals:

for packets moving over a LAN:
- for any tcp or udp packets:
- get:
    - ip address
    - send/receive ports
    - raw message
- prepare to hand off this information to a downstream processor that takes the pcap parts and outputs a new deserialized data (using the ip address, ports, and protocol the downstream processor will deserialize the raw message to a new format). We can expect that this crate will be used in a larger rust project as a constituent component, rather than needing to add functionality for sending the data somewhere.

>> NOTE: we included some additional packet metadata in case it might be useful in the future, but only the information described above is essential at this point in the project.

issues:
- packet headers management seems to be kind of complicated when we include issues like VLAN Tagging etc. which may or may not be something we experience
- general code design for a rust project and usage of crates like pcap



