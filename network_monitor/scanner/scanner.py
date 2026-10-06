"""
scanner.py
Discovers devices currently on the local network.

Two modes are supported:
1. ARP TABLE MODE (default, no admin/root needed): reads the OS's existing
   ARP table (built from normal network traffic). Good for getting started
   immediately on any laptop.
2. ACTIVE SCAN MODE (needs scapy + admin/root): actively sends ARP requests
   to discover every device on the subnet, even ones the OS hasn't talked
   to recently. More thorough — use this once your team is comfortable
   running Python with elevated privileges.

Start with ARP TABLE MODE to get the whole pipeline working end to end,
then upgrade to ACTIVE SCAN MODE for the "real" version of the project.
"""

import re
import socket
import subprocess
import platform
import time
import urllib.request
import urllib.error

import oui_database


def lookup_vendor_online(mac):
    """
    Fallback for when the local offline table doesn't recognize a MAC
    prefix. Queries the free api.macvendors.com API, which covers the
    full official IEEE registry (much bigger than our offline list).

    Requires internet access. Fails silently (returns "unknown") on any
    network error, timeout, or rate-limit — this is a "nice extra," not
    something the tool depends on to function.

    Note: the free tier of this API is rate-limited (roughly 1 request/sec
    per IP), which is why this should only be called ONCE per new device,
    never on every scan cycle — see how it's used in main.py.
    """
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "network-monitor-student-project"})
        with urllib.request.urlopen(req, timeout=3) as response:
            vendor = response.read().decode("utf-8").strip()
            return vendor if vendor else "unknown"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "unknown"  # API doesn't recognize this prefix either
        print(f"[scanner] Online vendor lookup failed ({e.code}) — using 'unknown'.")
        return "unknown"
    except Exception as e:
        print(f"[scanner] Online vendor lookup unavailable: {e}")
        return "unknown"


# Common mDNS service types that phones, smart TVs, printers, and IoT
# devices advertise themselves on. Reverse DNS and NetBIOS rarely work for
# these devices, but most of them broadcast a friendly name via one of
# these — this is closer to how commercial tools like Fing identify phones.
MDNS_SERVICE_TYPES = [
    "_http._tcp.local.",
    "_device-info._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_ipp._tcp.local.",
    "_workstation._tcp.local.",
    "_androidtvremote2._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_raop._tcp.local.",
]


def discover_mdns_hostnames(timeout=3):
    """
    Listens for mDNS (Bonjour/Avahi) broadcasts on the local network for
    `timeout` seconds and builds a map of {ip: hostname}.

    This works in two phases, since guessing service types in advance is
    unreliable (different routers/phones/IoT devices announce wildly
    different service types):
    1. META-DISCOVERY: query "_services._dns-sd._udp.local." — a special
       mDNS query that asks "what service types exist on this network at
       all?" (e.g. it might return "_wifiMeshAP._tcp.local.",
       "_googlecast._tcp.local.", etc. — whatever's actually present)
    2. TARGETED BROWSE: browse each discovered service type specifically
       to get the actual device names and IP addresses

    Returns an empty dict (and prints a warning) if zeroconf isn't
    installed — the rest of the tool still works fine without it.
    """
    try:
        from zeroconf import Zeroconf, ServiceBrowser
    except ImportError:
        print("[scanner] zeroconf not installed — skipping mDNS discovery. "
              "Run: pip install zeroconf")
        return {}

    discovered_types = set()
    discovered_hosts = {}

    class _TypeListener:
        """Phase 1: just record which service types exist."""
        def add_service(self, zc, service_type, name):
            discovered_types.add(name)

        def update_service(self, zc, service_type, name):
            pass

        def remove_service(self, zc, service_type, name):
            pass

    class _HostListener:
        """Phase 2: resolve actual devices for a specific service type."""
        def add_service(self, zc, service_type, name):
            try:
                info = zc.get_service_info(service_type, name)
                if info and info.addresses:
                    ip = socket.inet_ntoa(info.addresses[0])
                    hostname = info.server.rstrip(".") if info.server else name
                    discovered_hosts[ip] = hostname
            except Exception:
                pass  # a single bad response shouldn't crash the whole scan

        def update_service(self, zc, service_type, name):
            pass

        def remove_service(self, zc, service_type, name):
            pass

    zc = Zeroconf()

    # Phase 1: find out what service types actually exist on this network.
    # Give this the FULL timeout — responses can arrive anytime within the
    # window, not necessarily in the first couple seconds.
    ServiceBrowser(zc, "_services._dns-sd._udp.local.", _TypeListener())
    time.sleep(timeout)

    # Phase 2: browse each discovered type (plus our known common ones,
    # in case a device responds to a specific browse but not the meta-query)
    all_types = discovered_types | set(MDNS_SERVICE_TYPES)
    host_listener = _HostListener()
    browsers = [ServiceBrowser(zc, t, host_listener) for t in all_types]

    time.sleep(timeout)  # give devices time to respond
    zc.close()

    return discovered_hosts


def get_hostname(ip, mdns_map=None):
    """
    Tries to resolve a human-readable device name for an IP address.

    Tries three methods in order, since no single one works for every
    device type:
    1. mDNS lookup (best for phones, smart TVs, printers, IoT devices) —
       pass in the dict from discover_mdns_hostnames() so we don't re-scan
       mDNS for every single device
    2. Reverse DNS lookup (works if your router/DNS server supports it —
       best for routers and some PCs)
    3. NetBIOS name lookup via `nbtstat -A <ip>` (Windows-only, often the
       only way to get a name for Windows devices on a home network)

    Returns "unknown" if none of the three resolve a name — this can still
    happen for some IoT devices and locked-down phones; MAC address still
    uniquely identifies them either way.
    """
    # Method 1: mDNS (checked first — best coverage for phones/IoT)
    if mdns_map and ip in mdns_map:
        return mdns_map[ip]

    # Method 2: reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    # Method 3: NetBIOS lookup (Windows only)
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(
                ["nbtstat", "-A", ip], text=True, timeout=3,
                stderr=subprocess.DEVNULL,
            )
            # Look for a line like: "ADARSHSINGH-LT <00>  UNIQUE  Registered"
            for line in output.splitlines():
                match = re.match(r"\s*([A-Za-z0-9\-_]+)\s+<00>\s+UNIQUE", line)
                if match:
                    return match.group(1)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return "unknown"


def is_broadcast_or_multicast(mac):
    """
    Filters out non-device MAC addresses that show up in ARP tables but
    aren't actual devices: the broadcast address and multicast addresses
    (used by protocols like mDNS/UPnP, not real computers/phones).
    """
    mac = mac.lower()
    if mac == "ff:ff:ff:ff:ff:ff":
        return True
    if mac.startswith("01:00:5e"):  # IPv4 multicast range
        return True
    if mac.startswith("33:33"):  # IPv6 multicast range
        return True
    return False


def get_devices_from_arp_table():
    """
    Reads the OS's existing ARP table. Works on Windows, macOS, and Linux
    without needing root/admin privileges. Returns a list of dicts:
    [{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}, ...]
    Broadcast/multicast addresses are filtered out automatically.
    """
    system = platform.system()
    devices = []

    try:
        if system == "Windows":
            output = subprocess.check_output(["arp", "-a"], text=True)
            # Example line: "  192.168.1.5           aa-bb-cc-dd-ee-ff     dynamic"
            for line in output.splitlines():
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", line
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    if not is_broadcast_or_multicast(mac):
                        devices.append({"ip": ip, "mac": mac})
        else:
            # macOS and Linux both support `arp -a`
            output = subprocess.check_output(["arp", "-a"], text=True)
            # Example line: "? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ..."
            for line in output.splitlines():
                match = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).lower()
                    if not is_broadcast_or_multicast(mac):
                        devices.append({"ip": ip, "mac": mac})

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[scanner] Could not read ARP table: {e}")

    return devices


def get_local_subnet():
    """
    Auto-detects your local subnet in CIDR form (e.g. "192.168.29.0/24")
    based on your machine's own IP address, instead of requiring you to
    hardcode it. Assumes a standard /24 home network, which covers the
    vast majority of home/personal Wi-Fi setups.
    """
    try:
        # This doesn't actually send anything — it's a trick to get the
        # local IP by "connecting" to a public address and inspecting
        # which local interface the OS would use.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Assume /24: keep the first three octets, zero out the last
        octets = local_ip.split(".")
        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        return subnet
    except Exception as e:
        print(f"[scanner] Could not auto-detect subnet: {e}")
        return None


def get_devices_active_scan(subnet=None, timeout=3):
    """
    ACTIVE SCAN MODE — requires: pip install scapy, running with
    admin/root privileges, and (on Windows) Npcap installed
    (https://npcap.com — install with "WinPcap API-compatible mode" checked).

    Sends a real ARP request to EVERY possible address on the subnet and
    waits for replies. This finds devices the passive ARP table method
    misses entirely — anything that hasn't recently talked to your laptop
    (a phone sitting idle, a printer, an IoT device) still has to respond
    to a direct ARP request if it's alive on the network.

    If subnet is None, auto-detects it from your current IP.
    Returns [] and prints a clear message if scapy/Npcap/permissions
    aren't set up — this is expected to fail without the extra setup
    above, and the rest of the tool keeps working fine without it.
    """
    if subnet is None:
        subnet = get_local_subnet()
        if subnet is None:
            print("[scanner] Skipping active scan — could not determine subnet.")
            return []

    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        print("[scanner] scapy not installed — skipping active scan. "
              "Run: pip install scapy")
        return []

    try:
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered, _ = srp(packet, timeout=timeout, verbose=False)

        devices = []
        for sent, received in answered:
            mac = received.hwsrc.lower()
            if not is_broadcast_or_multicast(mac):
                devices.append({"ip": received.psrc, "mac": mac})

        return devices

    except PermissionError:
        print("[scanner] Active scan needs administrator privileges. "
              "Close this terminal and re-open PowerShell as Administrator, "
              "then run this again.")
        return []
    except OSError as e:
        print(f"[scanner] Active scan failed — is Npcap installed? "
              f"Download from https://npcap.com. Error: {e}")
        return []


def lookup_vendor(mac, allow_online_fallback=True):
    """
    Looks up the manufacturer for a MAC address's OUI (vendor prefix).
    Tries the local offline table first (instant, no internet needed,
    covers ~167 common vendors). If that returns "unknown" and
    allow_online_fallback is True, tries the online API as a second pass
    (covers the full IEEE registry, but needs internet + is rate-limited).
    """
    vendor = oui_database.lookup_vendor(mac)
    if vendor != "unknown" or not allow_online_fallback:
        return vendor
    return lookup_vendor_online(mac)


if __name__ == "__main__":
    # Quick manual test: run `python scanner.py` to see devices on your network
    found = get_devices_from_arp_table()
    print(f"Found {len(found)} device(s) in ARP table:")
    for d in found:
        vendor = lookup_vendor(d["mac"])
        print(f"  IP: {d['ip']:<16} MAC: {d['mac']:<18} Vendor: {vendor}")