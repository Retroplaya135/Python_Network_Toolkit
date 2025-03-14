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

# Code Overview
```
+-------------------------------------+
|        Python Network Toolkit      |
|   (Command-line networking tool)   |
+-------------------------------------+
        |          |          |          |          |          |
        v          v          v          v          v          v
+----------------+  +----------------+  +----------------+  +----------------+  
| Ping Utility  |  |  DNS Lookup     |  |  Traceroute    |  |  Port Scanner  |
| (ICMP check)  |  | (Resolve IP)    |  | (Find hops)   |  | (Scan ports)   |
+----------------+  +----------------+  +----------------+  +----------------+
        |          
        v          
+----------------+
| Packet Sniffer | 
| (Monitor net)  |
+----------------+
        |
        v
+----------------+
| IP Geolocation |
| (Find location)|
+----------------+
```

## Pre-Requisites
Install the required dependencies:
```bash
pip install scapy requests
```

---

# Core Network Utilities

```
+------------------------------------------------+
|            Networking Commands                |
+------------------------------------------------+
| 🔹 Ping Utility                               |
|   - Sends ICMP echo requests                 |
| 🔹 DNS Lookup                                |
|   - Resolves domain to IP                     |
| 🔹 Traceroute                                |
|   - Traces network path                       |
| 🔹 Port Scanner                              |
|   - Scans TCP ports (SYN scan)               |
| 🔹 Packet Sniffing                           |
|   - Captures network packets                 |
| 🔹 IP Geolocation                            |
|   - Fetches geo-location for an IP           |
+------------------------------------------------+
```


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

# Command Flow
```
+----------------------+
| User Executes Command |
+----------------------+
        |
        v
+----------------------+
|  Argument Parser    |
|  (argparse module)  |
+----------------------+
        |
        v
+----------------------+
|  Process Request    |
|  (Choose function)  |
+----------------------+
        |
        v
+----------------------+
|  Execute Networking |
|  Functions         |
+----------------------+
        |
        v
+----------------------+
|  Return Output      |
|  (Success/Error)    |
+----------------------+
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

### Trace the Route
Trace the network path to a target host:
```bash
python network_toolkit.py traceroute --target google.com
```

### Port Scan
Scan open ports (default: top 1000 ports):
```bash
python network_toolkit.py port-scan --target 192.168.1.10
```

# Port Scan Flow 

```
+----------------------+
| User Inputs Target  |
| (e.g. 127.0.0.1)    |
+----------------------+
        |
        v
+----------------------+
| Generate SYN Packet |
+----------------------+
        |
        v
+----------------------+
| Send Packet to Port |
| (e.g. Port 80)     |
+----------------------+
        |
        v
+----------------------+
| Wait for Response  |
+----------------------+
        |
        v
+----------------------+
| Open / Closed?     |
+----------------------+

```

Scan specific ports:
```bash
python network_toolkit.py port-scan --target 127.0.0.1 --ports 22,80,443
```

### Packet Sniffing
Capture packets on the specified interface:
```bash
python network_toolkit.py sniff --interface eth0
```
> **Note**: Use `Ctrl+C` to stop sniffing.

### Locate an IP Address
Get the geographic location of an IP address:
```bash
python network_toolkit.py ip-loc --ip 8.8.8.8
```

```
+----------------------+
| Send ICMP packets   |
| (4 packets sent)    |
+----------------------+
        |
        v
+----------------------+
| Receive Replies     |
| Show latency times  |
+----------------------+
```


---

## Contributing
Feel free to open issues or contribute by submitting pull requests.

