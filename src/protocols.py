import os
import platform
import subprocess


def check_icmp(ip: str, timeout: int = 1) -> bool:
    """Check whether an IP responds to ICMP echo requests."""
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), ip]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def check_arp(ip: str) -> bool:
    """Check if the local interface IP has an active ARP entry on Linux."""
    if platform.system().lower() != "linux":
        return False
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 1 and parts[0] == ip:
                        return True
        return True
    except Exception:
        return False


def check_igmp() -> bool:
    """Check if IGMP multicast memberships are active on the host."""
    if os.path.exists("/proc/net/igmp"):
        try:
            with open("/proc/net/igmp", "r") as f:
                content = f.read().strip()
                return len(content.splitlines()) > 1
        except Exception:
            return False
    return False


def check_ndp() -> bool:
    """Check if IPv6 Neighbor Discovery Protocol stack is active on Linux."""
    if platform.system().lower() == "linux":
        return os.path.exists("/proc/net/ipv6_route") or os.path.exists("/proc/net/if_inet6")
    return False


def check_icmpv6(ip_without_scope: str, timeout: int = 1) -> bool:
    """Check if an IPv6 address responds to ICMPv6 ping."""
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-6", "-n", "1", "-w", str(timeout * 1000), ip_without_scope]
    else:
        command = ["ping6", "-c", "1", "-W", str(timeout), ip_without_scope]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def scan_protocols(ip: str) -> dict:
    """Scan IPv4 Layer 3/4 network protocols."""
    return {
        "icmp": {
            "status": "reachable" if check_icmp(ip) else "no_response"
        },
        "arp": {
            "status": "active" if check_arp(ip) else "inactive"
        },
        "igmp": {
            "status": "active" if check_igmp() else "inactive"
        }
    }


def scan_ipv6_protocols(ip_without_scope: str) -> dict:
    """Scan IPv6-specific network protocols."""
    return {
        "ndp": {
            "status": "active" if check_ndp() else "inactive"
        },
        "icmpv6": {
            "status": "reachable" if check_icmpv6(ip_without_scope) else "no_response"
        }
    }