# arp-spoofer
## Simple ARP Spoofer built with Python3 and Scapy

### Modules needed:  
- scapy: pip install --pre scapy (https://scapy.readthedocs.io/en/latest/installation.html)  
- opt-parse: pip install optparse-pretty (https://docs.python.org/3/library/optparse.html)

### Usage:  
arp-spoof.py [options]

Options:  
-  -h, --help            show this help message and exit  
-  -t TARGET, --target=TARGET Target IP Address  
-  -s SPOOF, --spoof=SPOOF    Spoofed IP Address (Usually the gateway)  
-  -b, --block                 Block packet forwarding to the target machine  
-  -a, --allow                 Allow packet forward to the target machine (default)

### Examples:  

If your gateway address is 172.16.178.2 and your target address is 172.16.178.129, the following command will spoof his MAC Address:  
python3 arp-spoof.py -t 172.16.178.129 -s 172.16.178.2

**The packet forwarding is allowed by default  
**The flag -b (--block) will block the packed forwarding, this will not allow the target machine to communicate with the router.  
**When stopped, the program will reset the ARP Table.
