from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6


def to_str(x):
    """
    将输入值转换为字符串。

    Args:
        x: 输入值，可能是bytes、str或其他类型。

    Returns:
        str or None: 转换后的字符串，如果输入为None则返回None。
    """
    if isinstance(x, bytes):
        # 如果是bytes类型，尝试解码为字符串，忽略无法解码的字符
        return x.decode(errors="ignore")
    if x is None:
        return None
    # 如果已经是其他类型，直接转为字符串
    return str(x)

def norm_domain(d) -> str:
    """统一域名格式：小写、去空白、补尾点（root '.' 保持）"""
    d = to_str(d)
    if d is None:
        return ""
    d = str(d).strip().lower()
    if d == "":
        return ""
    if d == ".":
        return "."
    if not d.endswith("."):
        d += "."
    return d

# -------- 从Answer和Authority节提取域名 --------
def extract_from_answer(rr):
    """
    从DNS资源记录（RR）的Answer或Authority节中提取相关的域名。

    Args:
        rr: Scapy的DNS资源记录对象。

    Returns:
        list: 提取到的域名列表。
    """
    names = []

    def add(x):
        """内部辅助函数，标准化并添加域名到列表。"""
        x = norm_domain(x)
        if x:
            names.append(x)

    rrtype = getattr(rr, "type", None) # 获取资源记录类型

    # 总是添加记录本身的名称（如 example.com. IN A ...）
    add(rr.rrname)
    # 根据不同的记录类型，添加特定字段的值作为域名
    if rrtype == 2:      # NS (Name Server)
        # Scapy may store NS target in nsdname or rdata depending on version
        add(getattr(rr, "nsdname", None))
        add(getattr(rr, "rdata", None))
    elif rrtype == 5:    # CNAME (Canonical Name)
        add(getattr(rr, "rdata", None)) # 添加CNAME指向的目标名称
    elif rrtype == 6:    # SOA (Start of Authority)
        add(getattr(rr, "mname", None)) # 添加主服务器名称
        add(getattr(rr, "rname", None)) # 添加管理员邮箱（通常也是域名格式）
    elif rrtype == 12:   # PTR (Pointer)
        add(getattr(rr, "ptrdname", None)) # 添加PTR指向的目标名称
    elif rrtype == 15:   # MX (Mail Exchanger)
        add(getattr(rr, "exchange", None)) # 添加邮件交换服务器名称
    elif rrtype == 33:   # SRV (Service Locator)
        add(getattr(rr, "target", None)) # 添加服务主机名
    elif rrtype == 39:   # DNAME
        add(getattr(rr, "rdata", None)) # 添加DNAME指向的目标名称
    elif rrtype in (64, 65):  # SVCB / HTTPS
        add(getattr(rr, "target", None)) # 添加SVCB/HTTPS记录的目标名称

    return names

# -------- 解析EDNS选项（主要是COOKIE） --------
def parse_edns_options(rr):
    """
    解析EDNS OPT资源记录中的选项，特别关注COOKIE选项。

    Args:
        rr: Scapy的EDNS OPT资源记录对象。

    Returns:
        list: 解析出的选项列表，例如 ["edns_cookie:abcdef..."]。
    """
    out = []
    try:
        # 获取原始选项数据
        raw = getattr(rr, "optdata", None)
        if not raw:
            return out
        i = 0
        while i + 4 <= len(raw):
            # 每个选项由4字节头部组成：2字节code + 2字节length
            code = int.from_bytes(raw[i:i + 2], "big") # 选项码
            ln = int.from_bytes(raw[i + 2:i + 4], "big") # 选项数据长度
            val = raw[i + 4:i + 4 + ln] # 选项数据内容
            i += 4 + ln
            if code == 10:  # RFC 7873 定义的COOKIE选项码
                out.append("edns_cookie:" + val.hex()) # 将cookie值转为十六进制字符串
    except:
        # 忽略解析过程中的任何错误
        pass
    return out
# -------- 从Additional节提取信息 --------
def extract_from_additional(rr, parse_cookie=True):
    """
    从DNS资源记录的Additional节中提取域名和选项。
    这个函数与extract_from_answer类似，但增加了对EDNS OPT记录的支持。

    Args:
        rr: Scapy的DNS资源记录对象。
        parse_cookie (bool): 是否解析EDNS COOKIE选项。

    Returns:
        list: 提取到的域名和选项列表。
    """
    names = []

    def add(x):
        """内部辅助函数，标准化并添加域名到列表。"""
        x = norm_domain(x)
        if x:
            names.append(x)

    rrtype = getattr(rr, "type", None)
    add(rr.rrname)

    # 处理常见的资源记录类型
    if rrtype == 2:      # NS
        # Scapy may store NS target in nsdname or rdata depending on version
        add(getattr(rr, "nsdname", None))
        add(getattr(rr, "rdata", None))
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
    elif rrtype == 41 and parse_cookie: # OPT (EDNS)
        # 如果是OPT记录且需要解析COOKIE，则调用专门的解析函数
        names.extend(parse_edns_options(rr))

    return names
# ---------------- 工具函数 ----------------
def get_ip_tuple(pkt):
    """
    从Scapy数据包中提取源IP和目标IP地址。

    Args:
        pkt: Scapy数据包对象。

    Returns:
        tuple: (源IP, 目标IP)。如果找不到IP层，则返回(None, None)。
    """
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def get_l4_ports(pkt):
    """
    从Scapy数据包中提取传输层（TCP或UDP）的源端口和目标端口。

    Args:
        pkt: Scapy数据包对象。

    Returns:
        tuple: (源端口, 目标端口)。如果找不到TCP或UDP层，则返回(None, None)。
    """
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    return None, None
