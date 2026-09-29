# NetCity

**An interactive network dashboard visualizer.**

NetCity discovers devices on your local network, collects useful information about them, and visualizes everything as an interactive dashboard. Each device appears as a configurable node/panel. The dashboard updates in real time as devices join, leave, or change state.

---

## Features (Roadmap)

- Discover devices on your local subnet
- Collect IP address, MAC address, hostname, vendor, open ports, and more
- Live interactive visualization – devices appear as configurable nodes
- Click any device to see detailed information
- Signal strength and connection quality indicators
- Network overview (gateway, subnet, network type, etc.)
- Cross-platform (Linux, macOS, Windows)
- Runs with proper privilege handling (sudo / Administrator)
- Export data as JSON for further analysis or integration

---

## Output Format

Outputs structured JSON data including:

- System information (hostname, OS, platform details)
- Network interface data (IPv4/IPv6 addresses, MAC addresses, interface names)
- Gateway information
- Per-interface IP details (type classification, CIDR, network range, broadcast)
- Collected services per IP:
  - `protocols`: ICMP reachability, TCP/UDP service status
  - `ports`: Open TCP/UDP ports with service names and states
- Network topology overview

---

## Usage

```bash
python netcity_self.py
```

Generates `outputs/netcity_self.json` with all collected data.