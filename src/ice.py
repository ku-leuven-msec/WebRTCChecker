import json
import sys
from scapy.all import rdpcap, UDP, IP, IPv6

# --- Configuration ---
IPINFO_TOKEN = "c5e82516cfad4a"
STUN_MAGIC_COOKIE = b'\x21\x12\xa4\x42'

ICE_MESSAGE_TYPES = {
    0x0001: "Binding Request",
    0x0101: "Binding Success Response",
    0x0111: "Binding Error Response",
}

ATTR_TYPES = {
    0x0006: "USERNAME", 0x0008: "MESSAGE-INTEGRITY", 0x0024: "PRIORITY",
    0x0025: "USE-CANDIDATE", 0x8022: "SOFTWARE", 0x8029: "ICE-CONTROLLED",
    0x802A: "ICE-CONTROLLING",
}

# --- IP Geolocation Handler ---
handler = None
if IPINFO_TOKEN and IPINFO_TOKEN != "YOUR_IPINFO_TOKEN_HERE":
    import ipinfo
    handler = ipinfo.getHandler(IPINFO_TOKEN)
else:
    print("[Warning] IPinfo token not set. Geolocation/ASN will be skipped.")

# --- Helper Functions ---
def parse_attributes(payload):
    """Manually parses STUN attributes, decoding text fields where appropriate."""
    attributes = {}
    offset = 20
    while offset < len(payload):
        try:
            attr_type = int.from_bytes(payload[offset:offset+2], 'big')
            attr_len = int.from_bytes(payload[offset+2:offset+4], 'big')
            offset += 4
            attr_value = payload[offset:offset+attr_len]

            attr_name = ATTR_TYPES.get(attr_type)
            if attr_name in ["SOFTWARE", "USERNAME"]:
                attributes[attr_name] = attr_value.decode('utf-8', errors='ignore')
            elif attr_name:
                attributes[attr_name] = attr_value.hex()

            offset += (attr_len + 3) & ~3
        except Exception:
            break
    return attributes

def analyze_ice_packet(pkt, attributes):
    """Analyzes a single ICE-related STUN packet."""
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    udp_layer = pkt.getlayer(UDP)
    payload = bytes(udp_layer.payload)
    msg_type_code = int.from_bytes(payload[0:2], 'big')
    tx_id = payload[8:20].hex()

    # --- Improved Library Parsing Logic ---
    library_str = attributes.get("SOFTWARE", "Unknown")
    lib_name = "Unknown"
    lib_version = "Unknown"
    versions_behind = "Cannot be determined automatically. Requires manual lookup."
    
    if library_str != "Unknown":
        if '-' in library_str:
            # Handles "Coturn-4.5.2 'dan Eider'"
            parts = library_str.split('-', 1)
            lib_name = parts[0].strip()
            lib_version = parts[1].split(' ')[0].strip("'")
        else:
            # Handles "libcoreice"
            lib_name = library_str.strip()
            # lib_version remains "Unknown"
        
    analysis = {
        "timestamp": float(pkt.time),
        "src": f"{ip_layer.src}:{udp_layer.sport}",
        "dst": f"{ip_layer.dst}:{udp_layer.dport}",
        "transaction_id": tx_id,
        "username": attributes.get("USERNAME"), # <-- Added username
        "is_ice_used": True,
        "ice_version_standard": "RFC 8445 (modern ICE)",
        "cleartext_passwords_in_check": False,
        "notes_on_passwords": "ICE passwords (ice-pwd) are not sent in checks. They are used to generate the MESSAGE-INTEGRITY HMAC. Check the signaling phase (SDP) for cleartext credentials.",
        "candidate_types_used": "Cannot be determined from this packet. This is defined in the signaling (SDP) 'a=candidate' lines.",
        "mdns_obfuscation_used": "Cannot be determined from this packet. Look for '.local' hostnames in signaling (SDP) 'a=candidate' lines.",
        "library_name": lib_name,
        "library_version": lib_version,
        "versions_behind": versions_behind
    }
    return analysis

def detect_ice_sessions(pcap_file, output_file):
    """Reads a pcap, finds ICE connectivity checks, and saves a report."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return

    grouped_ice = {}
    for pkt in packets:
        is_udp = pkt.haslayer(UDP)
        if not is_udp or len(bytes(pkt[UDP].payload)) < 20:
            continue

        payload = bytes(pkt[UDP].payload)
        if payload[4:8] != STUN_MAGIC_COOKIE:
            continue
        
        msg_type_code = int.from_bytes(payload[0:2], 'big')
        if msg_type_code not in ICE_MESSAGE_TYPES:
            continue

        try:
            attributes = parse_attributes(payload)
            if "PRIORITY" in attributes:
                info = analyze_ice_packet(pkt, attributes)
                tx_id = info["transaction_id"]
                grouped_ice.setdefault(tx_id, []).append(info)
        except Exception as e:
            pass

    with open(output_file, "w") as f:
        json.dump(grouped_ice, f, indent=2)

    total_packets = sum(len(v) for v in grouped_ice.values())
    print(f"[+] Extracted {total_packets} ICE-related STUN packets into {len(grouped_ice)} transactions.")
    print(f"[+] Results saved to '{output_file}'")

# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ice_analyzer.py <input.pcap> [output.json]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "ice_results.json"

    detect_ice_sessions(pcap_path, output_path)