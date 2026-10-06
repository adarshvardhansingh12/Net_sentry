"""
oui_database.py
A built-in (offline, no internet required) table mapping MAC address
vendor prefixes (OUIs) to manufacturer names.

This is a curated subset covering common consumer/enterprise vendors —
phones, laptops, routers, IoT devices — NOT the full IEEE registry (which
has 40,000+ entries and changes constantly). It's built this way on
purpose: a live demo shouldn't depend on downloading anything from the
internet or querying an external API mid-presentation.

For a production tool, you'd replace/supplement this with the official
IEEE OUI database (a free CSV download from ieee.org) — but for a
16-week student project, this offline table is more reliable and
demonstrates the same concept without a network dependency risk.

Format: 3-octet prefix (first half of a MAC address) -> vendor name.
"""

OUI_DATABASE = {
    # Apple
    "00:1B:63": "Apple", "00:1E:C2": "Apple", "00:23:12": "Apple",
    "00:25:00": "Apple", "28:CF:E9": "Apple", "3C:07:54": "Apple",
    "40:A6:D9": "Apple", "68:96:7B": "Apple", "7C:6D:62": "Apple",
    "8C:85:90": "Apple", "A4:83:E7": "Apple", "AC:BC:32": "Apple",
    "D0:23:DB": "Apple", "F0:99:B6": "Apple", "F4:5C:89": "Apple",

    # Samsung
    "00:12:FB": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung",
    "00:1D:25": "Samsung", "00:26:37": "Samsung", "08:37:3D": "Samsung",
    "34:23:87": "Samsung", "5C:0A:5B": "Samsung", "78:1F:DB": "Samsung",
    "8C:77:12": "Samsung", "C4:88:E5": "Samsung", "E8:50:8B": "Samsung",

    # Google
    "3C:5A:B4": "Google", "54:60:09": "Google", "F4:F5:D8": "Google",
    "94:EB:2C": "Google", "18:B4:30": "Google Nest",

    # Amazon
    "44:65:0D": "Amazon", "68:37:E9": "Amazon", "74:75:48": "Amazon",
    "AC:63:BE": "Amazon", "FC:65:DE": "Amazon",

    # Microsoft
    "00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft", "28:18:78": "Microsoft", "60:45:BD": "Microsoft",
    "7C:1E:52": "Microsoft", "7C:ED:8D": "Microsoft (Xbox)",

    # Intel
    "00:02:B3": "Intel", "00:03:47": "Intel", "00:0E:35": "Intel",
    "00:13:E8": "Intel", "00:1B:21": "Intel", "3C:97:0E": "Intel",
    "5C:E0:C5": "Intel", "A0:88:69": "Intel",

    # Dell
    "00:06:5B": "Dell", "00:14:22": "Dell", "00:1C:23": "Dell",
    "18:A9:9B": "Dell", "44:A8:42": "Dell", "B8:CA:3A": "Dell",
    "F8:B1:56": "Dell",

    # HP
    "00:0F:20": "HP", "00:1B:78": "HP", "00:23:7D": "HP",
    "3C:D9:2B": "HP", "70:5A:0F": "HP", "9C:8E:99": "HP",
    "D4:C9:EF": "HP",

    # Cisco
    "00:0A:41": "Cisco", "00:0E:D7": "Cisco", "00:1A:A1": "Cisco",
    "00:23:04": "Cisco", "58:97:1E": "Cisco", "6C:20:56": "Cisco",
    "F4:CF:E2": "Cisco",

    # TP-Link
    "00:27:19": "TP-Link", "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link",
    "54:C8:0F": "TP-Link", "98:DA:C4": "TP-Link", "EC:08:6B": "TP-Link",

    # Xiaomi
    "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi", "50:8F:4C": "Xiaomi",
    "64:09:80": "Xiaomi", "9C:99:A0": "Xiaomi", "F0:B4:29": "Xiaomi",

    # OnePlus
    "40:B0:FA": "OnePlus", "AC:C1:EE": "OnePlus", "C0:EE:FB": "OnePlus",

    # Realtek (common in cheap/embedded network chips)
    "00:E0:4C": "Realtek", "52:54:00": "Realtek / QEMU virtual NIC",

    # Raspberry Pi Foundation
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation", "D8:3A:DD": "Raspberry Pi Foundation",

    # Virtualization (very useful for lab/dev machines)
    "00:0C:29": "VMware", "00:1C:14": "VMware", "00:50:56": "VMware",
    "00:05:69": "VMware", "08:00:27": "VirtualBox", "00:15:5D": "Hyper-V",

    # Huawei
    "00:18:82": "Huawei", "00:1E:10": "Huawei", "00:25:9E": "Huawei",
    "10:47:80": "Huawei", "34:6B:D3": "Huawei", "70:72:3C": "Huawei",
    "F8:3D:FF": "Huawei",

    # ASUS
    "00:0C:6E": "ASUS", "00:1B:FC": "ASUS", "00:22:15": "ASUS",
    "08:60:6E": "ASUS", "1C:87:2C": "ASUS", "AC:22:0B": "ASUS",

    # Netgear
    "00:09:5B": "Netgear", "00:14:6C": "Netgear", "00:1B:2F": "Netgear",
    "20:E5:2A": "Netgear", "A0:04:60": "Netgear",

    # D-Link
    "00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:15:E9": "D-Link",
    "1C:7E:E5": "D-Link", "90:94:E4": "D-Link",

    # Sony
    "00:01:4A": "Sony", "00:1A:80": "Sony", "04:5D:4B": "Sony",
    "30:F9:ED": "Sony", "FC:0F:E6": "Sony", "BC:60:A7": "Sony (PlayStation)",

    # LG Electronics
    "00:1C:62": "LG Electronics", "00:1E:75": "LG Electronics",
    "10:F1:F2": "LG Electronics", "A0:39:F7": "LG Electronics",
    "C4:36:6C": "LG Electronics",

    # Networking chipset/silicon vendors
    "00:10:18": "Broadcom", "00:0A:F7": "Broadcom",
    "00:03:7F": "Qualcomm/Atheros", "8C:FD:F0": "Qualcomm/Atheros",

    # Belkin
    "00:11:50": "Belkin", "08:86:3B": "Belkin", "C0:56:27": "Belkin",

    # Ubiquiti (common in prosumer/small business networking)
    "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti", "68:D7:9A": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",

    # Printers
    "00:00:48": "Epson", "64:EB:8C": "Epson",
    "00:1E:8F": "Canon", "3C:2A:F4": "Canon",
    "00:1B:A9": "Brother", "30:05:5C": "Brother",

    # Laptops/PC manufacturers
    "00:22:5F": "Lenovo", "54:EE:75": "Lenovo", "F0:DE:F1": "Lenovo",
    "00:1D:8B": "Acer", "74:D4:35": "Acer",
    "00:23:CD": "Toshiba", "4C:1D:96": "Toshiba",

    # Smart home
    "EC:B5:FA": "Philips Hue", "00:17:88": "Philips Hue",
    "44:61:32": "Ecobee", "0C:47:C9": "Ring",

    # Gaming consoles
    "00:1B:7A": "Nintendo", "00:1F:32": "Nintendo",
    "04:03:D6": "Nintendo", "8C:56:C5": "Nintendo",
    "00:1F:A7": "Sony (PlayStation)",
}


def lookup_vendor(mac):
    """
    Looks up the manufacturer for a MAC address using the 3-octet OUI
    prefix. Returns "unknown" if the prefix isn't in our table — this is
    expected for less common vendors, randomized MAC addresses (many
    modern phones randomize the OUI portion too for privacy), and any
    vendor not covered by this deliberately-scoped offline list.
    """
    prefix = mac.upper()[0:8]
    return OUI_DATABASE.get(prefix, "unknown")