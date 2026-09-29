import ipaddress
import json
import os
import platform
import socket
import sys
import netifaces
import psutil

from ports import scan_ports
from protocols import scan_protocols, scan_ipv6_protocols


def is_admin() -> bool:
    """Check if the script is running with elevated privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def classify_ip(ip_str: str) -> str:
    """Classify an IP address as loopback, private, or public."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            return "loopback"
        elif ip_obj.is_private:
            return "private"
        else:
            return "public"
    except ValueError:
        return "unknown"


def get_default_gateway() -> dict:
    """Get the default gateway IP address and interface."""
    try:
        gws = netifaces.gateways()
        default_gw = gws.get("default", {}).get(netifaces.AF_INET)
        if default_gw:
            return {
                "ip": default_gw[0],
                "interface": default_gw[1]
            }
    except Exception as e:
        print(f"[-] Error getting gateway: {e}")
    return None


def get_network_services(ip: str) -> dict:
    """Scans local listening ports and protocol statuses for the given IP address."""
    ports_data = scan_ports(ip)
    protocols_data = scan_protocols(ip)

    protocols_data["tcp"] = {
        "status": "active" if len(ports_data.get("tcp", [])) > 0 else "inactive",
        "open_count": len(ports_data.get("tcp", []))
    }

    protocols_data["udp"] = {
        "status": "active" if len(ports_data.get("udp", [])) > 0 else "inactive",
        "open_count": len(ports_data.get("udp", []))
    }

    return {
        "protocols": protocols_data,
        "ports": ports_data
    }


def get_interface_details() -> list:
    """Collect information about all network interfaces, including active services."""
    interfaces = []

    for interface_name in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface_name)

        interface_data = {
            "name": interface_name,
            "ipv4": [],
            "ipv6": [],
            "mac": None,
        }

        # MAC address
        link_addresses = addrs.get(netifaces.AF_LINK, [])
        if link_addresses:
            mac = link_addresses[0].get("addr")
            if mac:
                interface_data["mac"] = mac

        # IPv4 Processing
        ipv4_addresses = addrs.get(netifaces.AF_INET, [])
        for ipv4 in ipv4_addresses:
            ip = ipv4.get("addr")
            if not ip:
                continue

            netmask = ipv4.get("netmask")
            broadcast = ipv4.get("broadcast")

            ipv4_data = {
                "address": ip,
                "type": classify_ip(ip),
                "netmask": netmask,
                "broadcast": broadcast,
                "cidr": None,
                "network": None,
                "prefix_length": None,
                "host_range": None,
                "services": None,
            }

            if netmask:
                try:
                    network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                    ipv4_data["cidr"] = str(network)
                    ipv4_data["network"] = str(network.network_address)
                    ipv4_data["prefix_length"] = network.prefixlen

                    if network.prefixlen < 31:
                        first_host = network.network_address + 1
                        last_host = network.broadcast_address - 1
                        ipv4_data["host_range"] = {
                            "first": str(first_host),
                            "last": str(last_host),
                        }
                except ValueError:
                    pass

            print(f"[*] Scanning services on local address: {ip}...")
            ipv4_data["services"] = get_network_services(ip)
            interface_data["ipv4"].append(ipv4_data)

        # IPv6 Processing
        ipv6_addresses = addrs.get(netifaces.AF_INET6, [])
        for ipv6 in ipv6_addresses:
            address = ipv6.get("addr")
            if not address:
                continue

            address_without_scope = address.split("%")[0]

            print(f"[*] Scanning IPv6 protocols on address: {address_without_scope}...")
            ipv6_protocols = scan_ipv6_protocols(address_without_scope)

            interface_data["ipv6"].append({
                "address": address,
                "address_without_scope": address_without_scope,
                "type": classify_ip(address_without_scope),
                "netmask": ipv6.get("netmask"),
                "services": {
                    "protocols": ipv6_protocols
                }
            })

        interfaces.append(interface_data)

    return interfaces


def collect_self_data() -> dict:
    """Collect complete self network and system inspection output."""
    return {
        "netcity_version": "0.1.0",
        "system": {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "platform": platform.platform()
        },
        "network": {
            "gateway": get_default_gateway(),
            "interfaces": get_interface_details()
        }
    }


def main():
    print("[*] Starting NetCity Self Network Inspection...")
    data = collect_self_data()

    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "netcity_self.json")

    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[+] Scan completed successfully. Results saved to '{output_path}'.")


if __name__ == "__main__":
    main()