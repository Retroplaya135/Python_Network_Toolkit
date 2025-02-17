#!/usr/bin/env python3
"""
NETWORK_TOOLKIT.PY

A single script that provides multiple networking utilities:
1. Ping a host
2. Perform DNS lookups
3. Traceroute a host
4. TCP Port scanning
5. Sniff network packets
6. IP geolocation lookup

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

Requirements:
    - Python 3.x
    - scapy (pip install scapy)
    - requests (pip install requests)

Usage:
    python network_toolkit.py --help
    python network_toolkit.py ping --target google.com --count 3
    python network_toolkit.py dns-lookup --domain google.com
    python network_toolkit.py traceroute --target google.com
    python network_toolkit.py port-scan --target 127.0.0.1 --ports 22,80,443
    python network_toolkit.py sniff --interface eth0
    python network_toolkit.py ip-loc --ip 8.8.8.8

"""

import sys
import argparse
import socket
import requests
from scapy.all import (
    sr1,
    IP,
    ICMP,
    UDP,
    TCP,
    DNS,
    DNSQR,
    DNSRR,
    traceroute,
    sniff
)

###############################################################################
#                              PING UTILITY
###############################################################################
def ping_host(target, count):
    """
    Ping a target host using ICMP requests via Scapy.

    :param target:  The hostname or IP address to ping.
    :param count:   Number of times to send ICMP echo requests.
    """
    print(f"[+] Pinging {target} {count} times...\n")
    for i in range(count):
        icmp_packet = IP(dst=target) / ICMP()
        reply = sr1(icmp_packet, timeout=2, verbose=0)
        if reply is not None:
            print(f"Reply from {target}: time={(reply.time - icmp_packet.time)*1000:.2f} ms (seq={i+1})")
        else:
            print(f"No response from {target} (seq={i+1})")


###############################################################################
#                              DNS LOOKUP
###############################################################################
def dns_lookup(domain):
    """
    Perform a DNS A record lookup using Scapy.

    :param domain:  The domain name to resolve.
    """
    print(f"[+] Looking up DNS records for {domain}\n")
    # Create a DNS query
    dns_req = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=domain))
    # Send the DNS query and wait for a response
    response = sr1(dns_req, timeout=3, verbose=0)
    if response is not None and response.haslayer(DNS):
        dns_resp = response.getlayer(DNS)
        if dns_resp and dns_resp.an:
            for i in range(dns_resp.ancount):
                rr = dns_resp.an[i]
                if rr.type == 1:  # A record
                    print(f"{domain} -> {rr.rdata}")
        else:
            print(f"No DNS answer found for {domain}")
    else:
        print("DNS query timed out or no response received.")


###############################################################################
#                              TRACEROUTE
###############################################################################
def traceroute_host(target):
    """
    Perform a traceroute to a given target using Scapy's built-in traceroute function.

    :param target:  The hostname or IP address to trace.
    """
    print(f"[+] Tracerouting {target}...\n")
    # scapy's traceroute returns a tuple (res, unans)
    # We'll just print out the summary.
    res, unans = traceroute(target, maxttl=30, verbose=0)
    print("\nTraceroute completed. Result summary:\n")
    res.show()


###############################################################################
#                              PORT SCANNING
###############################################################################
def tcp_port_scan(target, ports):
    """
    Scan TCP ports of a target host using SYN packets via Scapy.

    :param target:  The IP address or hostname to scan.
    :param ports:   List of ports to scan.
    """
    # Resolve target if it's a domain name
    try:
        ip_target = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Could not resolve {target}. Exiting.")
        return

    print(f"[+] Scanning TCP ports on {target} ({ip_target})\n")
    open_ports = []

    for port in ports:
        # Build the packet
        syn_packet = IP(dst=ip_target)/TCP(dport=port, flags="S")
        # Send packet and wait for response
        resp = sr1(syn_packet, timeout=0.5, verbose=0)
        
        if resp is not None:
            # If we get a SYN/ACK flags, port is open
            if resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                # Send a RST packet to gracefully close the open connection
                rst_packet = IP(dst=ip_target)/TCP(dport=port, flags="R")
                sr1(rst_packet, timeout=0.5, verbose=0)
    
    # Print results
    if open_ports:
        print(f"Open ports on {target}: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found (or all filtered).")


def parse_port_list(port_string):
    """
    Parse a comma-separated list of ports, or return top 1000 if not specified.

    :param port_string: A string like '22,80,443' or None
    :return:            A list of integer ports.
    """
    if not port_string:
        # Return a typical "top 1000" range or custom approach
        # Here we just do 1-1024 for demonstration
        return list(range(1, 1025))
    ports = []
    for p in port_string.split(','):
        try:
            ports.append(int(p.strip()))
        except ValueError:
            pass
    return ports


###############################################################################
#                              PACKET SNIFFING
###############################################################################
def sniff_packets(interface):
    """
    Sniff network packets on the specified interface using Scapy.

    :param interface: Network interface to sniff (e.g., 'eth0').
    """
    print(f"[+] Sniffing on interface {interface}. Press Ctrl+C to stop.\n")
    
    # Callback to process each packet
    def process_packet(packet):
        print(f"[*] Packet: {packet.summary()}")
    
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except Exception as e:
        print(f"[-] Error while sniffing: {e}")


###############################################################################
#                              IP GEOLOCATION
###############################################################################
def ip_locate(ip):
    """
    Locate an IP address using a free geolocation API (ipapi.co).

    :param ip:  The IP address to locate.
    """
    print(f"[+] Looking up location for IP: {ip}\n")
    try:
        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "error" in data and data["error"]:
                print(f"[-] Error: {data.get('reason', 'Unknown error')}")
            else:
                print("Country:     ", data.get("country_name", "N/A"))
                print("Region:      ", data.get("region", "N/A"))
                print("City:        ", data.get("city", "N/A"))
                print("Postal Code: ", data.get("postal", "N/A"))
                print("Latitude:    ", data.get("latitude", "N/A"))
                print("Longitude:   ", data.get("longitude", "N/A"))
                print("Timezone:    ", data.get("timezone", "N/A"))
        else:
            print(f"[-] Request returned status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during requests to IP API: {e}")


###############################################################################
#                              MAIN FUNCTION
###############################################################################
def main():
    parser = argparse.ArgumentParser(
        description="Network Toolkit - multiple networking utilities in one script."
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # ------------------------------
    # PING
    # ------------------------------
    ping_parser = subparsers.add_parser(
        "ping",
        help="Ping a host a specified number of times."
    )
    ping_parser.add_argument(
        "--target",
        required=True,
        help="Hostname or IP address to ping."
    )
    ping_parser.add_argument(
        "--count",
        type=int,
        default=4,
        help="Number of ICMP echo requests (default=4)."
    )
    
    # ------------------------------
    # DNS LOOKUP
    # ------------------------------
    dns_parser = subparsers.add_parser(
        "dns-lookup",
        help="Perform DNS A record lookup for a given domain."
    )
    dns_parser.add_argument(
        "--domain",
        required=True,
        help="Domain name to resolve."
    )
    
    # ------------------------------
    # TRACEROUTE
    # ------------------------------
    tr_parser = subparsers.add_parser(
        "traceroute",
        help="Perform a traceroute to a target."
    )
    tr_parser.add_argument(
        "--target",
        required=True,
        help="Hostname or IP address to traceroute."
    )
    
    # ------------------------------
    # PORT SCAN
    # ------------------------------
    ps_parser = subparsers.add_parser(
        "port-scan",
        help="Scan TCP ports on a target host."
    )
    ps_parser.add_argument(
        "--target",
        required=True,
        help="Target IP or hostname."
    )
    ps_parser.add_argument(
        "--ports",
        help="Comma-separated list of ports to scan (e.g. 22,80,443). "
             "If omitted, scans ports 1-1024."
    )
    
    # ------------------------------
    # SNIFF
    # ------------------------------
    sniff_parser = subparsers.add_parser(
        "sniff",
        help="Sniff network packets on a specified interface."
    )
    sniff_parser.add_argument(
        "--interface",
        required=True,
        help="Network interface to sniff (e.g., eth0)."
    )
    
    # ------------------------------
    # IP LOCATE
    # ------------------------------
    ip_parser = subparsers.add_parser(
        "ip-loc",
        help="Locate an IP address using a free geolocation API."
    )
    ip_parser.add_argument(
        "--ip",
        required=True,
        help="IP address to locate."
    )

    # Parse arguments
    args = parser.parse_args()

    # Check which command was chosen
    if args.command == "ping":
        ping_host(args.target, args.count)
    elif args.command == "dns-lookup":
        dns_lookup(args.domain)
    elif args.command == "traceroute":
        traceroute_host(args.target)
    elif args.command == "port-scan":
        ports = parse_port_list(args.ports)
        tcp_port_scan(args.target, ports)
    elif args.command == "sniff":
        sniff_packets(args.interface)
    elif args.command == "ip-loc":
        ip_locate(args.ip)
    else:
        parser.print_help()

if __name__ == "__main__":
    # Entry point to the script
    # Call the main function
    main()
