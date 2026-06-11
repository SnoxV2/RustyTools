# RustyTools — Network Diagnostics

Diagnostic tool for network, system and security administrators. Native GUI
application (egui), cross-platform: **Windows, macOS, Linux**.

## Features

### 📡 Continuous ping
- Ping multiple targets simultaneously (IP or FQDN, one per line)
- Configurable interval and timeout (typed fields, persisted)
- **PingPlotter-style latency graph** as the main view, with one colored line
  per target and red markers on packet loss
- Live statistics: sent, received, loss (%), last/min/avg/max RTT, jitter
- One timestamped CSV log file per target:
  `logs/ping/ping_<date>_<target>.csv` with
  `timestamp;target;ip;seq;status;rtt_ms;jitter_ms`
  (status: `OK`, `TIMEOUT` on packet loss, or `ERROR: …`)

Jitter is the variation between two consecutive RTTs; the table shows the
session average.

### 🛣 Traceroute (MTR-style)
- **WinMTR / PingPlotter-style live view**: the path is discovered once with
  the system traceroute, then every responding hop is probed continuously —
  each hop row shows loss %, sent, last/avg/best/worst latency and jitter
- Configurable hop limit (max hops), probe interval and probe timeout
- Optional reverse DNS on hops
- Multiple targets in parallel
- Logs per target: `logs/traceroute/discovery_<date>_<target>.log` (raw path
  discovery) and `logs/traceroute/mtr_<date>_<target>.csv` (every probe)
- Path discovery uses the system tool: `tracert` (Windows), `traceroute`
  (macOS/Linux), with a `tracepath` fallback on Linux

### Advanced source selection (Ping, Traceroute, DNS)
Each of these tabs has an **Advanced** section to pick the probe source —
default behavior (system routing) is unchanged unless you opt in:
- **Source interface**: choose among the detected interfaces (refreshable
  list); probes are bound to that interface's address (plus
  `SO_BINDTODEVICE` on Linux / `IP_BOUND_IF` on macOS)
- **Custom source IP**: bind probes to a specific local address
- Traceroute passes `-s`/`-i` to the system tool on macOS/Linux; Windows
  `tracert` has no source option so only the per-hop probing honors it
- For DNS the source applies to the custom servers (not the system resolver)

### 🌐 DNS lookup
- Resolve names with the **system DNS** and/or a list of **custom DNS
  servers** (8.8.8.8, 1.1.1.1, a local AD controller, …) and compare the
  answers side by side
- Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR — entering an IP
  automatically performs a reverse (PTR) lookup
- Per-query timing, one timestamped log file per run in `logs/dns/`

### 📇 ARP
- Lists the devices in the host ARP/neighbor table (`arp`/`ip neigh`):
  IP, MAC, interface, state
- **Vendor identification on demand** from the embedded IEEE OUI database
  (offline, no API rate limits)
- Table export (with vendors) to `logs/arp/`

### 🖧 Network configuration
- Hostname, DNS domain, DNS servers
- Interfaces: state (UP/DOWN), type, MAC, IPv4 + mask, IPv6, gateway, DNS,
  default interface
- Full routing table
- Raw output of the system tools (`ipconfig /all`, `ifconfig`, `ip addr`, …)
- Full report export to a text file in `logs/netconfig/`

### ⚙ Settings
- Log folder, selected with the native folder picker
- Settings (log folder, intervals, timeouts, hop limit, …) are saved
  automatically in the platform config directory and persist across restarts
- The `ping/`, `traceroute/`, `dns/`, `arp/` and `netconfig/` subfolders are
  created automatically inside the log folder
- Every feature page has a **Delete log files** button (with confirmation)
  that empties its own log subfolder, plus a **Clear results** button for
  the current view

## Building

Requires [Rust](https://rustup.rs) (2021 edition).

```bash
cargo build --release
```

The binary is `target/release/rustytools` (`rustytools.exe` on Windows).
Build on (or for) each target OS to get the three executables.

System dependencies on Linux (Debian/Ubuntu example) for the GUI and dialogs:

```bash
sudo apt install build-essential libgtk-3-dev libxcb-render0-dev \
  libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

## ICMP privileges

| OS | Behaviour |
|----|-----------|
| Windows | No privileges required (`IcmpSendEcho` API) |
| macOS | No privileges required (ICMP datagram socket) |
| Linux | Unprivileged socket when `net.ipv4.ping_group_range` allows it (the default on recent distributions); otherwise automatic fallback to a raw socket, which requires root or `setcap cap_net_raw+ep` |

If neither mode is available, the error is shown in the UI with the fix.

## Logs

All files are written under the log folder configured in Settings
(`Documents/RustyTools/logs` by default), in the `ping/`, `traceroute/`,
`dns/`, `arp/` and `netconfig/` subfolders. Every line is timestamped with
millisecond precision.
