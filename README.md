# Python Network Toolkit

A general-purpose Python-based network toolkit for network diagnostics and analysis.

---

## Features
- **Ping**: Check the reachability of a host.
- **DNS Lookup**: Resolve domain names to IP addresses.
- **Traceroute**: Trace the path packets take to a target host.
- **Port Scan**: Scan open ports on a target machine.
- **Packet Sniffer**: Capture packets on a specified network interface.
- **IP Geolocation**: Locate a given IP address geographically.

---

## Pre-Requisites
Install the required dependencies:
```bash
pip install scapy requests
```

---

## Usage
Run the tool with the following commands:
```bash
python network_toolkit.py --help
python network_toolkit.py ping --target <host> --count <count>
python network_toolkit.py dns-lookup --domain <domain>
python network_toolkit.py traceroute --target <host>
python network_toolkit.py port-scan --target <host> --ports <port1,port2,...>
python network_toolkit.py sniff --interface <interface>
python network_toolkit.py ip-loc --ip <ip-address>
```

---

## Examples

### Ping a Host
Ping a target host 4 times:
```bash
python network_toolkit.py ping --target google.com --count 4
```

### Perform a DNS Lookup
Resolve the IP address of a domain:
```bash
python network_toolkit.py dns-lookup --domain google.com
```
