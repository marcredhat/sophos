#!/usr/bin/env python3
"""
send_sophos_syslog.py — Generate and send realistic Sophos Firewall (SFOS) /
Sophos Central syslog to a DPM (Observo) self-hosted site Syslog source for
end-to-end pipeline validation.

Sophos Firewall sends logs as a syslog header followed by space-separated
key="value" pairs, always led by `device="SFW"`:

    <30>Mon DD HH:MM:SS <host> device="SFW" date=YYYY-MM-DD time=HH:MM:SS
        timezone="GMT" device_name="XG210" device_id=... log_id=... log_type="Firewall"
        log_component="Firewall Rule" log_subtype="Allowed" ... src_ip=... dst_ip=...

This emits the most common Sophos log types — Firewall (majority), IPS/IDP,
Web Filter, ATP (Advanced Threat Protection) and Anti-Virus — with realistic
fields. It is a TEST GENERATOR, not a field-for-field SFOS emulator, but it
carries enough canonical keys for the DPM Sophos parser to classify each line.

Usage:
    python3 send_sophos_syslog.py --host <DOCKER_HOST_IP> --port 8766 --count 20
    python3 send_sophos_syslog.py --host 127.0.0.1 --port 8766 --proto tcp --type all

Options:
    --host HOST     Target (Docker host IP or container IP). Default 127.0.0.1
    --port PORT     Target port (the DPM source port). Default 8766
    --proto {tcp,udp}   Transport. Default tcp
    --count N       Number of messages to send. Default 10
    --type {firewall,ips,web,atp,av,all}   Which log type(s). Default all
    --interval SEC  Delay between messages. Default 0.2
    --hostname NAME Syslog header host. Default sfw01
    --device NAME   Sophos device_name. Default XG210
    --tls           Wrap the TCP connection in TLS (for ports like 10010)
    --tls-insecure  With --tls, skip certificate verification
    --ca PATH       With --tls, CA bundle to verify the server cert
    --dry-run       Print messages instead of sending
"""
import argparse
import random
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

SRC_SUBNETS = ["10.0.1.", "10.0.2.", "192.168.10.", "172.16.5."]
DST_IPS = ["93.184.216.34", "151.101.1.69", "104.16.132.229",
           "8.8.8.8", "20.190.160.14", "185.199.108.153", "203.0.113.50"]
ZONES = [("LAN", "LAN"), ("LAN", "WAN"), ("DMZ", "WAN"), ("WAN", "DMZ"),
         ("VPN", "LAN"), ("WiFi", "WAN")]
IFACES = ["PortA", "PortB", "PortC", "PortD", "Port1", "Port2"]
USERS = ["jsmith", "mwong", "svc_backup", "", "ahmed", "admin"]
APPS = [
    ("HTTPS", "Web", "Browsers based", "Risk-3"),
    ("DNS", "Network", "Network protocol", "Risk-1"),
    ("SSH", "Remote Access", "Client server", "Risk-3"),
    ("BitTorrent", "P2P", "P2P", "Risk-5"),
    ("Microsoft RDP", "Remote Access", "Client server", "Risk-4"),
    ("YouTube", "Streaming Media", "Browser based", "Risk-2"),
]
FW_RULES = [
    (3, "LAN-to-WAN-Allow"), (7, "Block-P2P"), (12, "DMZ-Web-Inbound"),
    (1, "Default-Drop"), (9, "VPN-Access"),
]
IPS_SIGS = [
    (57608, "WEB SQL injection attempt", 4, "TCP"),
    (21055, "SERVER Apache Log4j RCE attempt", 5, "TCP"),
    (34123, "MALWARE Win32/Emotet C2 traffic", 5, "TCP"),
    (18002, "SCAN Nmap TCP port scan", 2, "TCP"),
    (44910, "EXPLOIT EternalBlue SMB", 5, "TCP"),
]
WEB_CATS = [
    ("Search Engines", "Allowed", "Allow"), ("Social Networking", "Allowed", "Allow"),
    ("Gambling", "Denied", "Deny"), ("Malware", "Denied", "Deny"),
    ("Phishing", "Denied", "Deny"), ("Streaming Media", "Allowed", "Warn"),
    ("Business", "Allowed", "Allow"),
]
URLS = [
    "https://www.google.com/search?q=x", "https://facebook.com/feed",
    "http://malware-host.example/payload.exe", "http://phish.example/login",
    "https://github.com/repo", "https://youtube.com/watch?v=abc",
]
MALWARE = [
    ("EICAR-AV-Test", "eicar.com"), ("Troj/Agent-AXNP", "invoice.exe"),
    ("Mal/Generic-S", "setup.bin"), ("CXmail/MalPE-AB", "doc.scr"),
]
ATP_THREATS = [
    ("C2/Generic-A", "Callback to known C2"),
    ("Botnet/Mirai", "Botnet traffic detected"),
    ("Data-Exfil", "Suspicious outbound transfer"),
]
DEVICE_ID = "C0100" + "".join(random.choice("0123456789ABCDEF") for _ in range(11))


def syslog_header(hostname):
    # PRI 30 = facility daemon(3)*8 + severity info(6)
    ts = datetime.now().strftime("%b %e %H:%M:%S")
    return f"<30>{ts} {hostname} "


def _common(device, log_type, component, subtype, status, log_id, priority="Information"):
    now = datetime.now(timezone.utc).astimezone()
    return (
        f'device="SFW" date={now:%Y-%m-%d} time={now:%H:%M:%S} timezone="GMT" '
        f'device_name="{device}" device_id={DEVICE_ID} log_id={log_id} '
        f'log_type="{log_type}" log_component="{component}" log_subtype="{subtype}" '
        f'status="{status}" priority={priority}'
    )


def _kv(d):
    return " ".join(f'{k}={v}' for k, v in d.items())


def rand_ip(prefix):
    return prefix + str(random.randint(2, 254))


def firewall_log(device):
    szone, dzone = random.choice(ZONES)
    rid, rname = random.choice(FW_RULES)
    allowed = rname not in ("Block-P2P", "Default-Drop")
    subtype = "Allowed" if allowed else "Denied"
    status = "Allow" if allowed else "Deny"
    app, cat, tech, risk = random.choice(APPS)
    src, dst = rand_ip(random.choice(SRC_SUBNETS)), random.choice(DST_IPS)
    sport, dport = random.randint(1025, 65000), random.choice([443, 80, 53, 22, 3389, 6881])
    proto = "UDP" if dport == 53 else "TCP"
    sb, rb = random.randint(200, 80000), random.randint(200, 400000)
    head = _common(device, "Firewall", "Firewall Rule", subtype, status, "0101011")
    body = _kv({
        "fw_rule_id": rid, "fw_rule_name": f'"{rname}"', "nat_rule_id": "0",
        "policy_type": "1", "user_name": f'"{random.choice(USERS)}"', "user_gp": '""',
        "ips_policy_id": "0", "appfilter_policy_id": str(random.randint(0, 9)),
        "application": f'"{app}"', "application_risk": f'"{risk}"',
        "application_technology": f'"{tech}"', "application_category": f'"{cat}"',
        "in_interface": f'"{random.choice(IFACES)}"', "out_interface": f'"{random.choice(IFACES)}"',
        "src_ip": src, "dst_ip": dst, "protocol": f'"{proto}"',
        "src_port": sport, "dst_port": dport,
        "sent_pkts": random.randint(1, 500), "recv_pkts": random.randint(1, 900),
        "sent_bytes": sb, "recv_bytes": rb,
        "tran_src_ip": "", "tran_src_port": "0", "tran_dst_ip": "", "tran_dst_port": "0",
        "srczonetype": f'"{szone if szone in ("LAN","DMZ","VPN","WiFi") else "WAN"}"',
        "srczone": f'"{szone}"', "dstzonetype": f'"WAN"', "dstzone": f'"{dzone}"',
        "dir_disp": '""', "connevent": '"Start"', "connid": f'"{random.randint(10**6,10**9)}"',
        "hb_health": '"No Heartbeat"',
    })
    return f"{head} {body}"


def ips_log(device):
    sid, name, sev, proto = random.choice(IPS_SIGS)
    src, dst = rand_ip(random.choice(SRC_SUBNETS)), random.choice(DST_IPS)
    head = _common(device, "IDP", "IPS", "Signatures",
                   "Detect" if sev < 5 else "Drop", "0204021", "Alert")
    body = _kv({
        "idp_policy_id": str(random.randint(1, 9)), "idp_policy_name": '"LAN-IPS"',
        "signature_id": sid, "signature_msg": f'"{name}"',
        "classification": '"Web Application Attack"', "rule_priority": sev,
        "src_ip": src, "dst_ip": dst, "protocol": f'"{proto}"',
        "src_port": random.randint(1025, 65000),
        "dst_port": random.choice([80, 443, 445, 22]),
        "platform": '"All"', "category": '"exploit"',
        "target": '"Server"', "unit": '""',
    })
    return f"{head} {body}"


def web_log(device):
    cat, subtype, action = random.choice(WEB_CATS)
    src, dst = rand_ip(random.choice(SRC_SUBNETS)), random.choice(DST_IPS)
    url = random.choice(URLS)
    code = 200 if action == "Allow" else 403
    head = _common(device, "Content Filtering", "HTTP", subtype, action, "0301011")
    body = _kv({
        "user_name": f'"{random.choice(USERS)}"', "src_ip": src, "dst_ip": dst,
        "protocol": '"TCP"', "src_port": random.randint(1025, 65000),
        "dst_port": random.choice([80, 443]),
        "url": f'"{url}"', "domain": f'"{url.split("/")[2]}"',
        "category": f'"{cat}"', "category_type": '"Acceptable"',
        "http_status": code, "content_type": '"text/html"',
        "web_policy_id": str(random.randint(1, 9)), "rule_id": str(random.randint(1, 20)),
        "sent_bytes": random.randint(200, 5000), "recv_bytes": random.randint(200, 90000),
        "user_agent": '"Mozilla/5.0"', "reason": ('""' if action == "Allow" else '"Blocked Category"'),
    })
    return f"{head} {body}"


def atp_log(device):
    tname, desc = random.choice(ATP_THREATS)
    src, dst = rand_ip(random.choice(SRC_SUBNETS)), random.choice(DST_IPS)
    head = _common(device, "ATP", "Network", "Drop", "Drop", "0501011", "Alert")
    body = _kv({
        "user_name": f'"{random.choice(USERS)}"', "src_ip": src, "dst_ip": dst,
        "threatname": f'"{tname}"', "event_type": f'"{desc}"',
        "protocol": '"TCP"', "src_port": random.randint(1025, 65000),
        "dst_port": random.choice([443, 80, 53]), "execution_path": '""',
        "ep_uuid": f'"{random.randint(10**9,10**12)}"', "login_user": f'"{random.choice(USERS)}"',
    })
    return f"{head} {body}"


def av_log(device):
    sig, fname = random.choice(MALWARE)
    src, dst = rand_ip(random.choice(SRC_SUBNETS)), random.choice(DST_IPS)
    head = _common(device, "Anti-Virus", "HTTP", "Virus", "Drop", "0401011", "Alert")
    body = _kv({
        "user_name": f'"{random.choice(USERS)}"', "src_ip": src, "dst_ip": dst,
        "protocol": '"TCP"', "src_port": random.randint(1025, 65000), "dst_port": "443",
        "virus": f'"{sig}"', "filename": f'"{fname}"',
        "url": f'"http://{random.choice(DST_IPS)}/{fname}"',
        "domain": f'"{random.choice(DST_IPS)}"', "ftp_url": '""',
        "quarantine": f'"{fname}.quarantine"', "action": '"Drop"',
    })
    return f"{head} {body}"


GEN = {"firewall": firewall_log, "ips": ips_log, "web": web_log,
       "atp": atp_log, "av": av_log}
ALL_WEIGHTS = [("firewall", 0.55), ("web", 0.20), ("ips", 0.12),
               ("av", 0.08), ("atp", 0.05)]


def make_one(kind, hostname, device):
    if kind == "all":
        r, cum = random.random(), 0.0
        kind = "firewall"
        for k, w in ALL_WEIGHTS:
            cum += w
            if r <= cum:
                kind = k
                break
    body = GEN[kind](device)
    return syslog_header(hostname) + body


def build_messages(n, kind, hostname, device):
    return [make_one(kind, hostname, device) for _ in range(n)]


def _maybe_tls(sock, host, tls, insecure, ca):
    if not tls:
        return sock
    if insecure:
        ctx = ssl._create_unverified_context()
    elif ca:
        ctx = ssl.create_default_context(cafile=ca)
    else:
        ctx = ssl.create_default_context()
    return ctx.wrap_socket(sock, server_hostname=host)


def send_tcp(host, port, count, kind, hostname, device, interval,
             tls=False, insecure=False, ca=None):
    raw = socket.create_connection((host, port), timeout=10)
    s = _maybe_tls(raw, host, tls, insecure, ca)
    proto = "tls" if tls else "tcp"
    try:
        for i in range(1, count + 1):
            m = make_one(kind, hostname, device)
            s.sendall((m + "\n").encode("utf-8"))
            print(f"[{proto}] sent {i}/{count}: {m[:100]}...")
            time.sleep(interval)
    finally:
        s.close()


def send_udp(host, port, count, kind, hostname, device, interval):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(1, count + 1):
        m = make_one(kind, hostname, device)
        s.sendto(m.encode("utf-8"), (host, port))
        print(f"[udp] sent {i}/{count}: {m[:100]}...")
        time.sleep(interval)
    s.close()


def main():
    ap = argparse.ArgumentParser(description="Send sample Sophos Firewall syslog to a DPM source.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--type", choices=["firewall", "ips", "web", "atp", "av", "all"], default="all")
    ap.add_argument("--interval", type=float, default=0.2)
    ap.add_argument("--hostname", default="sfw01")
    ap.add_argument("--device", default="XG210")
    ap.add_argument("--tls", action="store_true", help="wrap TCP in TLS (e.g. port 10010)")
    ap.add_argument("--tls-insecure", action="store_true", help="skip TLS cert verification")
    ap.add_argument("--ca", default="", help="CA bundle to verify the server cert")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.dry_run:
        print("\n".join(build_messages(args.count, args.type, args.hostname, args.device)))
        return 0

    wire = "tls" if (args.proto == "tcp" and args.tls) else args.proto
    print(f">> Sending {args.count} Sophos {args.type} log(s) to "
          f"{args.host}:{args.port}/{wire} (fresh per-message timestamps)")
    try:
        if args.proto == "tcp":
            send_tcp(args.host, args.port, args.count, args.type, args.hostname,
                     args.device, args.interval,
                     tls=args.tls, insecure=args.tls_insecure, ca=(args.ca or None))
        else:
            send_udp(args.host, args.port, args.count, args.type, args.hostname, args.device, args.interval)
    except OSError as e:
        print(f"ERROR: could not send to {args.host}:{args.port}/{args.proto}: {e}",
              file=sys.stderr)
        return 1
    print(">> Done. Check the DPM pipeline Ingest Rate graph and "
          "Event Search (XDR) for Sophos events (device=\"SFW\").")
    return 0


if __name__ == "__main__":
    sys.exit(main())
