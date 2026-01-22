import json
from collections import defaultdict
from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6


# ================== Config ==================
PCAP_FILE = "baidu.com_duobao.pcap"
OUT_FILE = "result_baidu_duobao1.json"

LOCAL_IP = "172.17.0.3"   # 递归解析器 IP
TIMEOUT = 5 * 1000000000               # 超时兜底（秒）

EXTRACT_ADDITIONAL = True     # 是否解析 Additional
PARSE_EDNS_COOKIE = False     # Additional 中是否解析 EDNS COOKIE
# ============================================


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
        return True   # IPv6 近似判断
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


# -------- Answer/Authority 提取 --------
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


# -------- EDNS COOKIE 解析 --------
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


# -------- Additional 提取 --------
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


# -------- 父区回溯绑定（不计数）--------
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


# -------- 将域名统一加入 roots（不计数）--------
def unify_into_roots(roots, names, flows, domain_root, ts):
    for root_key in list(roots):
        if root_key not in flows:
            continue
        flows[root_key]["last_update"] = ts
        for d in names:
            flows[root_key]["domains"].add(d)
            domain_root[d].add(root_key)


# -------- 仅真实 DNS 包计数 --------
def increment_counts(roots, names, flows):
    for root_key in list(roots):
        if root_key not in flows:
            continue
        for d in names:
            flows[root_key]["counts"][d] += 1


# -------- 写出 JSON 快照（覆盖写入数组）--------
def write_snapshot(finished, path):
    serial = []
    for f in finished:
        serial.append({
            "client": f["client"],
            "qname": f["qname"],
            "recursive_domains": sorted(list(f["domains"])),
            "counts": dict(f["counts"]),
            "start_time": int(f["start"]),  # 转换为整数
            "end_time": int(f["last_update"]),  # 转换为整数
        })
    with open(path, "w") as fp:
        json.dump(serial, fp, indent=2, ensure_ascii=False)


# -------- 结束单个 flow 并立即写出 --------
def finalize_flow(root_key, flows, finished):
    if root_key in flows:
        finished.append(flows[root_key])
        del flows[root_key]


# ================== 主逻辑 ==================
def parse_pcap():
    packets = rdpcap(PCAP_FILE)
    flows = {}
    domain_root = defaultdict(set)
    finished = []

    for p in packets:
        if not p.haslayer(DNS):
            continue
        dns = p[DNS]
        ts = (p.time - 1763068395) * 1000000000 # 转换为纳秒时间戳（与本地时间对齐）
        finalize_expired(flows, finished, ts)

        srcip, dstip = get_ip_tuple(p)
        sport, dport = get_l4_ports(p)
        if srcip is None or dstip is None:
            continue

        qname = None
        if getattr(dns, "qd", None):
            qname = to_str(dns.qd.qname)

        # (1) client -> resolver: 创建 root-flow
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
            continue

        # (2) Response
        if dns.qr == 1 and qname:

            # === 情况 A：resolver -> client 的最终响应 === 结束flow ===
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
                    write_snapshot(finished, OUT_FILE)
                    continue

            # === 情况 B：upstream -> resolver 的中间响应 ===
            if srcip != LOCAL_IP and dstip == LOCAL_IP:
                names_real = set([qname])
                for i in range(getattr(dns, "ancount", 0)):
                    names_real |= set(extract_from_answer(dns.an[i]))
                for i in range(getattr(dns, "nscount", 0)):
                    names_real |= set(extract_from_answer(dns.ns[i]))
                if EXTRACT_ADDITIONAL:
                    for i in range(getattr(dns, "arcount", 0)):
                        names_real |= set(extract_from_additional(dns.ar[i], PARSE_EDNS_COOKIE))

                # ⚙️ 修正关键逻辑：仅依据 qname 进行关联，防止跨 flow 污染
                seeds = set(domain_root.get(qname, set()))
                inferred = set()

                if not seeds:
                    roots_q = bind_roots_by_parent(qname, flows, domain_root)
                    if roots_q:
                        seeds |= roots_q
                        inferred.add(qname)

                if not seeds:
                    continue

                unify_into_roots(seeds, names_real | inferred, flows, domain_root, ts)
                increment_counts(seeds, names_real, flows)

    # flush 所有未完成 flow
    for key in list(flows.keys()):
        finished.append(flows[key])
        del flows[key]

    write_snapshot(finished, OUT_FILE)
    return finished


def main():
    parse_pcap()
    print(f"✅ Done. 输出：{OUT_FILE}")


if __name__ == "__main__":
    main()
