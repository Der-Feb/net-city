import socket
import psutil

TCP_SERVICES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 
    443: "HTTPS", 445: "SMB", 587: "SMTP Submission", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8025: "Mailpit / MailHog", 8080: "HTTP Alternate", 
    8443: "HTTPS Alternate", 11434: "Ollama API",
}

UDP_SERVICES = { 
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP", 123: "NTP", 137: "NetBIOS Name Service", 
    138: "NetBIOS Datagram Service", 161: "SNMP", 162: "SNMP Trap", 500: "IKE", 514: "Syslog", 1900: "SSDP", 
    5353: "mDNS", 56761: "Ephemeral / Dynamic Port",
}

def get_tcp_service(port):
    return TCP_SERVICES.get(port, "Unknown")

def get_udp_service(port):
    return UDP_SERVICES.get(port, "Unknown")

def scan_ports(ip):
    """
    Finds open TCP/UDP ports strictly listening on the targeted interface IP,
    or specifically bound to global wildcards (0.0.0.0 / ::).
    """
    tcp_results = []
    udp_results = []

    seen_tcp = set()
    seen_udp = set()

    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.laddr:
                continue

            # Safely unpack tuple vs namedtuple
            if hasattr(conn.laddr, "ip"):
                l_ip, l_port = conn.laddr.ip, conn.laddr.port
            else:
                l_ip, l_port = conn.laddr[0], conn.laddr[1]

            # Strict binding match: exact interface IP match OR explicit wildcard
            # Wildcards are mapped strictly to loopback or global bindings to prevent cross-interface duplication
            is_direct_match = (l_ip == ip)
            is_wildcard_match = (l_ip in ("0.0.0.0", "::") and ip == "127.0.0.1")

            if is_direct_match or is_wildcard_match:

                # TCP Listening sockets
                if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
                    if l_port not in seen_tcp:
                        seen_tcp.add(l_port)
                        tcp_results.append({
                            "port": l_port,
                            "service": get_tcp_service(l_port),
                            "state": "open",
                            "bound_to": l_ip
                        })

                # UDP Sockets
                elif conn.type == socket.SOCK_DGRAM:
                    if l_port not in seen_udp:
                        seen_udp.add(l_port)
                        udp_results.append({
                            "port": l_port,
                            "service": get_udp_service(l_port),
                            "state": "open",
                            "bound_to": l_ip
                        })

    except Exception as e:
        print(f"[-] Warning reading network connections: {e}")

    tcp_results.sort(key=lambda x: x["port"])
    udp_results.sort(key=lambda x: x["port"])

    return {
        "tcp": tcp_results,
        "udp": udp_results,
    }