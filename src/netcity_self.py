import ipaddress
import os
import platform
import socket
import sys
import psutil

import netifaces

# Import port scanning and protocol functionality from local modules
from ports import scan_ports
from protocols import scan_protocols


def is_admin():
    """Check if the script is running with elevated privileges."""
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except Exception:
        return False


def request_admin():
    """Inform the user they need to run with sudo/admin."""
    print("\n[!] This script requires elevated privileges to run.")
    if os.name == "nt":
        print("    → Right-click the terminal and choose 'Run as administrator'.")
    else:
        print("    → Run it with:  sudo python netcity_self.py")
    print()
    sys.exit(1)


def get_system_details():
    """Collect basic system information about the machine."""
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }


def get_gateway_details():
    """Collect default IPv4 gateway information."""
    gateway = netifaces.gateways()
    default_gateway = gateway.get("default", {}).get(netifaces.AF_INET)

    if not default_gateway:
        return None

    gateway_ip, interface = default_gateway

    return {
        "ip": gateway_ip,
        "interface": interface,
    }


def classify_ip(ip):
    """Classify IP addresses."""
    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "loopback"
        if address.is_private:
            return "private"
        if address.is_link_local:
            return "link_local"
        if address.is_multicast:
            return "multicast"
        if address.is_reserved:
            return "reserved"

        return "public"
    except ValueError:
        return "invalid"


def get_network_services(ip):
    """Collect port states and non-port protocols for a given IP."""
    return {
        "protocols": scan_protocols(ip),
        "ports": scan_ports(ip),
    }


def get_interface_details():
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

        link_addresses = addrs.get(netifaces.AF_LINK, [])
        if link_addresses:
            mac = link_addresses[0].get("addr")
            if mac:
                interface_data["mac"] = mac

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
                    network = ipaddress.ip_network(
                        f"{ip}/{netmask}", strict=False
                    )
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

        ipv6_addresses = addrs.get(netifaces.AF_INET6, [])
        for ipv6 in ipv6_addresses:
            address = ipv6.get("addr")
            if not address:
                continue

            address_without_scope = address.split("%")[0]
            interface_data["ipv6"].append({
                "address": address,
                "address_without_scope": address_without_scope,
                "type": classify_ip(address_without_scope),
                "netmask": ipv6.get("netmask"),
            })

        interfaces.append(interface_data)

    return interfaces


def get_netcity_data():
    """Assemble system, interface, and service information."""
    return {
        "netcity_version": "0.1.0",
        "system": get_system_details(),
        "network": {
            "gateway": get_gateway_details(),
            "interfaces": get_interface_details(),
        },
    }


def save_json(data, filename="netcity_self.json"):
    """Save output to JSON inside outputs directory."""
    import json
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    output_dir = project_root / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / filename

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    print(f"\n[+] JSON saved to: {output_file}")


if __name__ == "__main__":
    print("Starting NetCity Self Scan...")
    data = get_netcity_data()
    save_json(data)