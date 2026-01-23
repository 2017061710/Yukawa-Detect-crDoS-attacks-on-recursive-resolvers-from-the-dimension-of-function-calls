import argparse
import json
import time
from collections import defaultdict

import redis
from redis.exceptions import ConnectionError
from scapy.all import sniff, get_if_addr
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6


# ================== Config ==================
LOCAL_IP = None   # Resolver IP (auto from interface)
TIMEOUT = 5 * 1000000000               # Timeout fallback (seconds)

EXTRACT_ADDITIONAL = True     # Parse Additional section
PARSE_EDNS_COOKIE = False     # Parse EDNS COOKIE in Additional

REDIS_QUEUE_NAME = "dns_analysis_results"
_REDIS_CLIENT = None
# ============================================


# ---------------- Redis ----------------
def connect_redis():
    try:
        r = redis.Redis(host="localhost", port=6379, db=0, socket_connect_timeout=2)
        r.ping()
        print("Connected to Redis server")
        return r
    except ConnectionError:
        print("Cannot connect to Redis. Is the service running?")
        print("Try: sudo systemctl restart redis-server")
        return None


# ---------------- Utils ----------------
def get_ip_tuple(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def get_l4_ports(pkt):
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    return None, None


def to_str(x):
    if isinstance(x, bytes):
        return x.decode(errors="ignore")
    if x is None:
        return None
    return str(x)


def looks_like_ip(s: str):
    if not isinstance(s, str):
        return False
    if ":" in s:
        return True   # Approximate IPv6 check
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


# -------- Answer/Authority extraction --------
def extract_from_answer(rr):
    names = []

    def add(x):
        x = to_str(x)
        if x:
            names.append(x)

    rrtype = getattr(rr, "type", None)

    add(rr.rrname)
    if rrtype == 2:      # NS
        add(getattr(rr, "nsdname", None))
    elif rrtype == 5:    # CNAME
        add(getattr(rr, "rdata", None))
    elif rrtype == 6:    # SOA
        add(getattr(rr, "mname", None))
        add(getattr(rr, "rname", None))
    elif rrtype == 12:   # PTR
        add(getattr(rr, "ptrdname", None))
    elif rrtype == 15:   # MX
        add(getattr(rr, "exchange", None))
    elif rrtype == 33:   # SRV
        add(getattr(rr, "target", None))
    elif rrtype == 39:   # DNAME
        add(getattr(rr, "rdata", None))
    elif rrtype in (64, 65):  # SVCB / HTTPS
        add(getattr(rr, "target", None))

    return names


# -------- EDNS COOKIE parsing --------
def parse_edns_options(rr):
    out = []
    try:
        raw = getattr(rr, "optdata", None)
        if not raw:
            return out
        i = 0
        while i + 4 <= len(raw):
            code = int.from_bytes(raw[i:i+2], "big")
            ln = int.from_bytes(raw[i+2:i+4], "big")
            val = raw[i+4:i+4+ln]
            i += 4 + ln
            if code == 10:  # COOKIE
                out.append("EDNS_COOKIE:" + val.hex())
    except:
        pass
    return out


# -------- Additional extraction --------
def extract_from_additional(rr, parse_cookie=False):
    names = []

    def add(x):
        x = to_str(x)
        if x:
            names.append(x)

    rrtype = getattr(rr, "type", None)
    add(rr.rrname)

    if rrtype == 2:
        add(getattr(rr, "nsdname", None))
    elif rrtype == 5:
        add(getattr(rr, "rdata", None))
    elif rrtype == 6:
        add(getattr(rr, "mname", None))
        add(getattr(rr, "rname", None))
    elif rrtype == 12:
        add(getattr(rr, "ptrdname", None))
    elif rrtype == 15:
        add(getattr(rr, "exchange", None))
    elif rrtype == 33:
        add(getattr(rr, "target", None))
    elif rrtype == 39:
        add(getattr(rr, "rdata", None))
    elif rrtype in (64, 65):
        add(getattr(rr, "target", None))
    elif rrtype == 41 and parse_cookie:
        names.extend(parse_edns_options(rr))

    return names


# -------- Timeout flush --------
def finalize_expired(flows, finished, now):
    expired = []
    for key, data in flows.items():
        if now - data["last_update"] >= TIMEOUT:
            expired.append(key)
    for key in expired:
        finished.append(flows[key])
        del flows[key]


# -------- Parent suffix binding (no counting) --------
def bind_roots_by_parent(name, flows, domain_root):
    roots = set()
    if not name:
        return roots
    for root_key, finfo in flows.items():
        root_q = finfo.get("qname")
        if not root_q:
            continue
        if root_q == name or root_q.endswith("." + name):
            roots.add(root_key)
    if roots:
        domain_root[name].update(roots)
    return roots


# -------- Unify domain names into roots (no counting) --------
def unify_into_roots(roots, names, flows, domain_root, ts):
    for root_key in list(roots):
        if root_key not in flows:
            continue
        flows[root_key]["last_update"] = ts
        for d in names:
            flows[root_key]["domains"].add(d)
            domain_root[d].add(root_key)


# -------- Count only real DNS packets --------
def increment_counts(roots, names, flows):
    for root_key in list(roots):
        if root_key not in flows:
            continue
        for d in names:
            flows[root_key]["counts"][d] += 1


# -------- JSON snapshot (push to Redis list) --------
def write_snapshot(finished):
    if _REDIS_CLIENT is None:
        return
    print(f"Writing snapshot with {len(finished)} finished flows to Redis...")
    serial = []
    for f in finished:
        serial.append({
            "client": f["client"],
            "qname": f["qname"],
            "recursive_domains": sorted(list(f["domains"])),
            "counts": dict(f["counts"]),
            "start_time": int(f["start"]),
            "end_time": int(f["last_update"]),
        })

    try:
        _REDIS_CLIENT.delete(REDIS_QUEUE_NAME)
        for record in serial:
            _REDIS_CLIENT.rpush(REDIS_QUEUE_NAME, json.dumps(record))
        finished.clear()
    except Exception as e:
        print(f"Error pushing to Redis: {e}")


# -------- Finalize a single flow and snapshot --------
def finalize_flow(root_key, flows, finished):
    if root_key in flows:
        finished.append(flows[root_key])
        del flows[root_key]


# ================== Main logic ==================
def parse_live(iface):
    flows = {}
    domain_root = defaultdict(set)
    finished = []

    def process_packet(p):
        if not p.haslayer(DNS):
            return
        dns = p[DNS]
        ts = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        # try:
            
        # except AttributeError:
        #     ts = time.monotonic_ns()
        finalize_expired(flows, finished, ts)

        srcip, dstip = get_ip_tuple(p)
        sport, dport = get_l4_ports(p)
        if srcip is None or dstip is None:
            return

        qname = None
        if getattr(dns, "qd", None):
            qname = to_str(dns.qd.qname)

        # (1) client -> resolver: create root-flow
        if dns.qr == 0 and qname and dstip == LOCAL_IP and getattr(dns, "rd", 0) == 1:
            root_key = (srcip, sport, qname)
            if root_key not in flows:
                flows[root_key] = {
                    "client": f"{srcip}:{sport}",
                    "qname": qname,
                    "domains": {qname},
                    "counts": defaultdict(int),
                    "start": ts,
                    "last_update": ts,
                }
            domain_root[qname].add(root_key)
            flows[root_key]["last_update"] = ts
            return

        # (2) Response
        if dns.qr == 1 and qname:

            # Case A: resolver -> client final response, end flow
            if srcip == LOCAL_IP:
                root_key = (dstip, dport, qname)
                if root_key in flows:
                    names_real = set([qname])
                    for i in range(getattr(dns, "ancount", 0)):
                        names_real |= set(extract_from_answer(dns.an[i]))
                    for i in range(getattr(dns, "nscount", 0)):
                        names_real |= set(extract_from_answer(dns.ns[i]))
                    if EXTRACT_ADDITIONAL:
                        for i in range(getattr(dns, "arcount", 0)):
                            names_real |= set(extract_from_additional(dns.ar[i], PARSE_EDNS_COOKIE))

                    seeds = {root_key}
                    unify_into_roots(seeds, names_real, flows, domain_root, ts)
                    increment_counts(seeds, names_real, flows)

                    finalize_flow(root_key, flows, finished)
                    write_snapshot(finished)
                    return

            # Case B: upstream -> resolver intermediate response
            if srcip != LOCAL_IP and dstip == LOCAL_IP:
                names_real = set([qname])
                for i in range(getattr(dns, "ancount", 0)):
                    names_real |= set(extract_from_answer(dns.an[i]))
                for i in range(getattr(dns, "nscount", 0)):
                    names_real |= set(extract_from_answer(dns.ns[i]))
                if EXTRACT_ADDITIONAL:
                    for i in range(getattr(dns, "arcount", 0)):
                        names_real |= set(extract_from_additional(dns.ar[i], PARSE_EDNS_COOKIE))

                # Critical fix: associate only by qname to avoid cross-flow pollution
                seeds = set(domain_root.get(qname, set()))
                inferred = set()

                if not seeds:
                    roots_q = bind_roots_by_parent(qname, flows, domain_root)
                    if roots_q:
                        seeds |= roots_q
                        inferred.add(qname)

                if not seeds:
                    return

                unify_into_roots(seeds, names_real | inferred, flows, domain_root, ts)
                increment_counts(seeds, names_real, flows)

    try:
        sniff(iface=iface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("Stopped by user")

    # flush all unfinished flows
    for key in list(flows.keys()):
        finished.append(flows[key])
        del flows[key]

    write_snapshot(finished)
    return finished


def main():
    parser = argparse.ArgumentParser(description="Live DNS analysis with Scapy")
    parser.add_argument("-i", "--iface", required=True, help="Interface name")
    args = parser.parse_args()

    global LOCAL_IP
    global _REDIS_CLIENT

    LOCAL_IP = get_if_addr(args.iface)
    if not LOCAL_IP:
        print(f"Failed to get IP from interface: {args.iface}")
        return

    print(f"Using interface: {args.iface}, local IP: {LOCAL_IP}")
    _REDIS_CLIENT = connect_redis()
    if _REDIS_CLIENT is None:
        return

    print("Start sniffing... (Ctrl+C to stop)")
    parse_live(args.iface)


if __name__ == "__main__":
    main()
