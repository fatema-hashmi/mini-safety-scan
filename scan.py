# scan.py — super simple port scan with tips (beginner-friendly)
# Usage:
#   python scan.py --host 127.0.0.1 --top 30 --out report.txt

import socket
import time
import sys

COMMON_PORTS = [
    # (port, name, why_it_exists, basic_risk, basic_fix)
    (20,  "FTP-data",     "file transfer (legacy)",      "rarely needed; weak auth",            "disable FTP; use SFTP"),
    (21,  "FTP",          "file transfer (legacy)",      "clear-text creds",                    "disable FTP; use SFTP"),
    (22,  "SSH",          "remote admin",                "brute-force if exposed",              "use strong password/keys; change port; allowlist IPs"),
    (23,  "Telnet",       "remote admin (legacy)",       "clear-text; very unsafe",             "disable Telnet; use SSH"),
    (25,  "SMTP",         "mail server",                 "open relay risk",                     "use auth; restrict to mail server only"),
    (53,  "DNS",          "name service",                "amplification attacks",               "don’t expose resolver publicly"),
    (80,  "HTTP",         "web server",                  "no TLS; mixed content",               "prefer 443; redirect to HTTPS"),
    (110, "POP3",         "mail download (legacy)",      "clear-text auth",                     "disable; use POP3S/IMAPS if needed"),
    (143, "IMAP",         "mail access",                 "clear-text if not TLS",               "use IMAPS (993)"),
    (443, "HTTPS",        "secure web",                  "weak TLS/ciphers if misconfigured",   "keep TLS certs updated; strong ciphers"),
    (3306,"MySQL",        "database",                    "default creds; data exposure",        "bind to localhost; firewall; strong creds"),
    (3389,"RDP",          "Windows remote desktop",      "bruteforce; ransomware entry",        "don’t expose to internet; strong creds; MFA/VPN"),
]

DEFAULT_TOP = 20  # scan first N from COMMON_PORTS


def parse_args(argv):
    host = "127.0.0.1"
    top = DEFAULT_TOP
    out = None
    i = 0
    while i < len(argv):
        if argv[i] == "--host" and i+1 < len(argv):
            host = argv[i+1]; i += 2
        elif argv[i] == "--top" and i+1 < len(argv):
            try:
                top = int(argv[i+1])
            except:
                top = DEFAULT_TOP
            i += 2
        elif argv[i] == "--out" and i+1 < len(argv):
            out = argv[i+1]; i += 2
        else:
            i += 1
    return host, max(1, min(top, len(COMMON_PORTS))), out


def host_is_up(host, timeout=1.0):
    # Try to resolve + connect to a safe port quickly (443). If it times out, we still scan.
    try:
        socket.gethostbyname(host)
        s = socket.create_connection((host, 443), timeout=timeout)
        s.close()
        return True
    except:
        return True  # don’t block scanning if 443 closed; we’ll just proceed


def scan_port(host, port, timeout=0.6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except:
        return False


def build_report(host, results):
    lines = []
    lines.append(f"Mini Safety Scan — {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Host: {host}")
    lines.append("")
    if not results:
        lines.append("No open ports found in the tested set.")
        return "\n".join(lines)

    lines.append("Open ports found:")
    for (port, name, why, risk, fix) in results:
        lines.append(f"- {port}/tcp ({name}) — {why}")
        lines.append(f"  Risk: {risk}")
        lines.append(f"  Fix:  {fix}")
    lines.append("")
    lines.append("General tips:")
    lines.append("- Close services you don’t use.")
    lines.append("- If a service must be open, use strong passwords/keys and keep it updated.")
    lines.append("- Don’t expose admin services (RDP/SSH/DB) directly to the internet; use VPN/MFA.")
    return "\n".join(lines)


def main():
    host, top, out = parse_args(sys.argv[1:])
    ports_to_scan = COMMON_PORTS[:top]

    print(f"[i] Scanning {host} — first {top} common ports...")
    up = host_is_up(host)
    if not up:
        print("[!] Host seems down or unreachable, proceeding anyway...")

    open_findings = []
    for (port, name, why, risk, fix) in ports_to_scan:
        is_open = scan_port(host, port)
        status = "OPEN" if is_open else "closed"
        print(f" - {port:>5}/tcp {name:<7} : {status}")
        if is_open:
            open_findings.append((port, name, why, risk, fix))

    report = build_report(host, open_findings)
    print()
    print(report)

    if out:
        try:
            with open(out, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\n[✓] Report saved to {out}")
        except Exception as e:
            print(f"[!] Could not write report: {e}")


if __name__ == "__main__":
    main()
