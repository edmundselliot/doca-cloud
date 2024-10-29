import sys

if len(sys.argv) < 2:
    print("Usage: python send_lacp.py <interface>")
    sys.exit(1)

from scapy.all import *
from scapy.contrib.lacp import SlowProtocol, LACP

lacp_pkt = Ether() / SlowProtocol() / LACP()

# Send the LACP packet
sendp(lacp_pkt, iface=sys.argv[1], count=5)

print("Sent 5 LACP packets from " + sys.argv[1])