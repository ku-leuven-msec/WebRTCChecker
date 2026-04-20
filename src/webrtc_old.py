
import json
import sys
import argparse
import pyshark
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
from ciphers import CIPHER_SUITES_IANA, WEAK_CIPHER_PREFIXES, WEAK_SUBSTRINGS

# --- Helper Functions (No changes needed here) ---
def get_session_key(pkt):
    try:
        key_parts = sorted([(pkt.ip.src, pkt[pkt.transport_layer].srcport), (pkt.ip.dst, pkt[pkt.transport_layer].dstport)])
        return f"{key_parts[0][0]}:{key_parts[0][1]}-{key_parts[1][0]}:{key_parts[1][1]}"
    except AttributeError: return None

def is_cipher_strong(cipher_name):
    if not cipher_name: return False
    if any(cipher_name.upper().startswith(prefix) for prefix in WEAK_CIPHER_PREFIXES): return False
    if any(weak_part in cipher_name.upper() for weak_part in WEAK_SUBSTRINGS): return False
    return True

def analyze_certificate(cert_hex_string, date):
    try:
        #print("[DEBUG] Analyzing certificate data...")
        cert_data = bytes.fromhex(cert_hex_string)
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        is_self_signed = cert.issuer == cert.subject
        #print(f"[DEBUG] Certificate validity check: {cert.not_valid_before_utc} <= {date} <= {cert.not_valid_after_utc}")

        is_valid_period = cert.not_valid_before_utc <= date <= cert.not_valid_after_utc
        try: san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName); sans = [str(name) for name in san_ext.value]
        except x509.ExtensionNotFound: sans = []
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else "Not Found"
        subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else "Not Found"
        fingerprint = cert.fingerprint(hashes.SHA256())
        formatted_fp = ":".join(f"{b:02X}" for b in fingerprint)

        return {
            "self_signed": is_self_signed,
            "validity_period_ok": is_valid_period,
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_until": cert.not_valid_after_utc.isoformat(),
            "issuer_cn": issuer_cn,
            "subject_cn": subject_cn,
            "subject_alternative_names": sans,
            "key_exchange_algorithm": cert.signature_algorithm_oid._name,
            "fingerprint": formatted_fp

        }
    except Exception as e:
        return {"error": f"Failed to parse certificate: {e}"}

def analyze_tls_sessions(pcap_file, output_file, verbose=False):
    sessions = {}
    print("[+] Analyzing all TLS and DTLS packets...")
    try:
        # Use a broader filter to capture both protocols
        cap = pyshark.FileCapture(pcap_file, display_filter="tls or dtls")
        cap.load_packets()
        total_packets = len(cap)
    except Exception as e:
        print(f"[ERROR] Error opening pcap file: {e}"); return

    for pkt in tqdm(cap, total=total_packets, desc="Processing packets"):
        key = get_session_key(pkt)
        if not key: continue

        # Determine which protocol layer is present (TLS or DTLS)
        protocol_layer = None
        protocol_name = None
        if hasattr(pkt, 'tls'):
            protocol_layer = pkt.tls
            protocol_name = "TLS"
        elif hasattr(pkt, 'dtls'):
            protocol_layer = pkt.dtls
            protocol_name = "DTLS"
        
        if not protocol_layer:
            continue

        if key not in sessions:
            if verbose: print(f"\n[INFO] Packet {pkt.number}: Discovered new {protocol_name} session: {key}")
            sessions[key] = {
                "protocol": protocol_name,
                "client_endpoint": "N/A",
                "server_endpoint": "N/A",
                "total_bytes": 0, 
                "client_hello": {},
                "server_hello": {},
                "certificate_details": {}
            }
        session = sessions[key]
        pkt_num = pkt.number

        try:
            sessions[key]["total_bytes"] += int(pkt.length) # Use actual packet length
        except AttributeError:
            pass # Ignore packets without length attribute

        transport_layer = pkt.tcp if hasattr(pkt, 'tcp') else pkt.udp

        if hasattr(protocol_layer, 'handshake_type'):
            # 1. Get Client Hello data if we haven't successfully gotten cipher suites yet
            if protocol_layer.handshake_type == '1' and not session["client_hello"].get("offered_cipher_suites"):
                if verbose: print(f"  [DEBUG] Packet {pkt_num}: Found ClientHello. Attempting to parse...")

                if session["client_endpoint"] == "N/A":
                    session["client_endpoint"] = f"{pkt.ip.src}:{transport_layer.srcport}"
                    if verbose: print(f"    [INFO] Identified client: {session['client_endpoint']}")
                if session["server_endpoint"] == "N/A":
                    session["server_endpoint"] = f"{pkt.ip.dst}:{transport_layer.dstport}"
                    if verbose: print(f"    [INFO] Identified server: {session['server_endpoint']}")
                
                try: 
                    session["client_hello"]["version"] = protocol_layer.handshake_version.showname_value
                except AttributeError:
                    pass
                try:
                    raw_values = [field.raw_value for field in protocol_layer.handshake_ciphersuite.all_fields]
                    cipher_names = [CIPHER_SUITES_IANA.get(c.lower(), {}).get('name', f"Unknown (0x{c})") for c in raw_values]                    
                    session["client_hello"]["offered_cipher_suites"] = cipher_names
                    if verbose: print(f"    [SUCCESS] Extracted {len(cipher_names)} offered cipher suites.")
                except (AttributeError, KeyError):
                    if verbose: print(f"    [FAIL] Could not extract offered cipher suites.")
                # (Add extension parsing logic here if needed)

            # 2. Get Server Hello data if not already found
            if protocol_layer.handshake_type == '2' and not session["server_hello"].get("chosen_crypto_suite"):
                if verbose: print(f"  [DEBUG] Packet {pkt_num}: Found ServerHello. Attempting to parse...")
                try:
                    chosen_hex = protocol_layer.handshake_ciphersuite.raw_value
                    chosen_name = CIPHER_SUITES_IANA.get(chosen_hex, {}).get('name', f"Unknown (0x{chosen_hex})")
                    session["server_hello"]["chosen_crypto_suite"] = chosen_name
                    session["server_hello"]["is_encryption_strong"] = is_cipher_strong(chosen_name)
                    if verbose: print(f"    [SUCCESS] Extracted chosen cipher.")
                except AttributeError:
                    if verbose: print(f"    [WARN] Could not extract chosen cipher suite.")

            # 3. Get Certificate data if not already found
            if not session["certificate_details"] or "error" in session["certificate_details"]:
                if hasattr(protocol_layer, 'handshake_certificate'):
                    if verbose: print(f"  [DEBUG] Packet {pkt_num}: Found certificate data. Attempting to parse...")
                    cert_hex = protocol_layer.handshake_certificate.replace(':', '')

                    date = pkt.sniff_time.astimezone(timezone.utc) if hasattr(pkt, 'sniff_time') else datetime.now(timezone.utc)

                    session["certificate_details"] = analyze_certificate(cert_hex, date)
                    if "error" not in session["certificate_details"]:
                        if verbose: print(f"    [SUCCESS] Extracted and parsed certificate.")
                    else:
                        if verbose: print(f"    [ERROR] Failed to parse certificate data: {session['certificate_details']['error']}")
    cap.close()

    # Post-processing and report generation...
    for session in sessions.values():
        if session.get("client_hello") and session["client_hello"].get("offered_cipher_suites"):
            offered = session["client_hello"]["offered_cipher_suites"]
            weak_found = [c for c in offered if not is_cipher_strong(c)]
            session["client_hello"]["security_summary"] = {"offers_weak_ciphers": len(weak_found) > 0, "weak_ciphers_list": weak_found}
            
    report = list(sessions.values())
    final_report = [s for s in report if s.get("client_hello") or s.get("server_hello") or s.get("certificate_details")]
    
    print("[+] Sorting report to prioritize DTLS sessions...")
    final_report.sort(key=lambda s: s.get('protocol') != 'DTLS')

    print("\n" + "="*50 + "\nANALYSIS SUMMARY\n" + "="*50)
    if not final_report:
        print(f"[!] Found {len(sessions)} potential TLS/DTLS session(s), but could not extract any handshake details.")
    else:
        print(f"[+] Successfully analyzed {len(final_report)} of {len(sessions)} detected TLS/DTLS session(s).")
    
    with open(output_file, "w") as f:
        json.dump(final_report, f, indent=2)
    print(f"[+] Full report saved to '{output_file}'")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python webrtc.py <input.pcap> [output.json]")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "webrtc_analysis.json"
    verbose = True if len(sys.argv) > 3 else False

    analyze_tls_sessions(pcap_file, output_file, verbose)