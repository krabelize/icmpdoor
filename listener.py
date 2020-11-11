#!/usr/bin/python3
import sys
import os
from scapy.all import *

def check_scapy():
    try:
        import scapy
    except ImportError:
        print("Please install scapy module")

def icmpshell(pkt):
    if pkt[ICMP].type == 0:
        if pkt[ICMP].id == 19000:
            newpkt = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n','')
            print(newpkt)

sniff(iface="eth0", prn=icmpshell, filter="icmp", store="0")
