# Python_Network_Toolkit
General purpose python based Network toolkit

## Pre-Requisites:

pip install scapy requests

## Usage:
    python network_toolkit.py --help
    python network_toolkit.py ping --target google.com --count 3
    python network_toolkit.py dns-lookup --domain google.com
    python network_toolkit.py traceroute --target google.com
    python network_toolkit.py port-scan --target 127.0.0.1 --ports 22,80,443
    python network_toolkit.py sniff --interface eth0
    python network_toolkit.py ip-loc --ip 8.8.8.8
    
## Examples:
    
### Ping a host 4 times
python network_toolkit.py ping --target google.com --count 4

### Perform a DNS lookup
python network_toolkit.py dns-lookup --domain google.com

### Traceroute a host
python network_toolkit.py traceroute --target google.com

### Port scan a target (default top 1000 ports)
python network_toolkit.py port-scan --target 192.168.1.10

### Sniff packets on interface eth0 (Ctrl+C to stop)
python network_toolkit.py sniff --interface eth0

### Locate an IP address
python network_toolkit.py ip-loc --ip 8.8.8.8

