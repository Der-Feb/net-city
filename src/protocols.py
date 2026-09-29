import platform
import subprocess

def check_icmp(ip, timeout=2):
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
    
def scan_protocols(ip):
    """Check protocols that don't use TCP/UDP ports."""
    return {
        "icmp": {
            "status": "reachable" if check_icmp(ip) else "no_response"
        }
    }


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    protocols = scan_protocols(target_ip)

    print(f"\nProtocol scan for {target_ip}")
    print("=" * 50)
    for protocol, information in protocols.items():
        print(f"{protocol.upper():<10} {information['status']}")