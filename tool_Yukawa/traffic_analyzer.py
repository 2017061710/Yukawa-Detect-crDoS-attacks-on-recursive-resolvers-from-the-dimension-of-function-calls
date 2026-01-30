import queue
import time
import threading
from scapy.all import sniff, get_if_addr
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP
from delay_queue import DelayQueue
from utils import *
from collections import defaultdict
from typing import List, Tuple
from scapy.all import conf
conf.max_list_count = 100000


class DNSTrafficAnalyzer:
    
    def __init__(self):
        self.__pkt_index = 1
        self.__report_queue = queue.Queue()
        self.__local_ip = None
        self.__timeout_ns = 5 * 1_000_000_000
        self.__extract_additional = True
        self.__parse_edns_cookie = False

        # 0 未启动捕包 1 已启动捕包
        self.__status = 0
        self.__delay_queue = DelayQueue()
        self.__time_offset = 3_000_000_000 # 3秒
        
        self.__flows_lock = threading.Lock()
        self.__flows = {}
        self.__domain2flows = defaultdict(set)
        self.__tcp_streams = {}
        self.__tcp_stream_max_buffer = 4 * 1024 * 1024
        
    def listen(self, iface):
        self.__status = 1
        if not self.__local_ip:
            self.__local_ip = get_if_addr(iface)
            if not self.__local_ip:
                print(f"Failed to get IP from interface: {iface}")
                return False
        print("Start sniffing... (Ctrl+C to stop)")
        # 启动一个线程执行超时处理
        threading.Thread(target=self.__timeout_process, daemon=True).start()
        sniff(iface=iface, prn=self.__process_packet, store=False)
    
    def get_report(self):
        return self.__report_queue.get()
    def __timeout_process(self):
        """
        超时发送
        """
        for flow_key in self.__delay_queue:
            with self.__flows_lock:
                if flow_key not in self.__flows:
                    # 流已经被提前删除了
                    continue
                self.__finalize_flow(flow_key)
                
    def __update_flows(self,flow_keys:List[Tuple],ts):
        for flow_key in flow_keys:
            if flow_key not in self.__flows:
                continue
            if self.__flows[flow_key]["last_update"] == ts:
                continue
            self.__flows[flow_key]["last_update"] = ts
            self.__delay_queue.put(flow_key, ts + self.__timeout_ns)
            
    def __infer_flows_by_domain(self,domain):
        """
        尝试通过域名关联查询流，只推断，不更新，O(n)
        """
        if domain.startswith("_."):
            domain = domain[2:]
        infer_flow_keys = set()
        for root_key in self.__flows:
            qname = self.__flows[root_key]["qname"]
            if qname == domain or qname.endswith("." + domain):
                infer_flow_keys.add(root_key)
        if not infer_flow_keys:
            for d in self.__domain2flows:
                if d == domain or d.endswith("." + domain):
                    infer_flow_keys |= self.__domain2flows[d]
        return infer_flow_keys
    
    def __add_domains_to_flows_with_lock(self,flow_keys:List[Tuple],domains:List[str]):
        """
        注意：在获取锁之后，再调用函数
        """
        for flow_key in flow_keys:
            if flow_key not in self.__flows:
                continue
            for domain in domains:
                if not domain:
                    continue
                self.__flows[flow_key]["domains"].add(domain)
                self.__domain2flows[domain].add(flow_key)
    
    def __increase_domains_count(self,flow_keys:List[Tuple],domains:List[str]):
        """
        注意：在获取锁之后，再调用函数
        """
        for flow_key in flow_keys:
            if flow_key not in self.__flows:
                continue
            for domain in domains:
                if not domain:
                    continue
                self.__flows[flow_key]["counts"][domain] += 1
    
    def __finalize_flow(self,flow_key):
        """
        注意：在获取锁之后，再调用函数
        """
        if flow_key not in self.__flows:
            return
        flow = self.__flows[flow_key]
        del self.__flows[flow_key]
        self.__report_queue.put({
            "client": flow["client"], # 客户端地址
            "qname": flow["qname"], # 初始查询的域名
            "recursive_domains": sorted(list(flow["domains"])), # 该查询递归解析的所有域名
            "counts": dict(flow["counts"]), # 每个域名出现的次数
            "start_time": int(flow["start"]), # 查询开始时间
            "end_time": int(flow["last_update"])+self.__time_offset, # 查询结束时间
        })
        for domain in flow["domains"]:
            self.__domain2flows[domain].remove(flow_key)
            if len(self.__domain2flows[domain]) == 0:
                del self.__domain2flows[domain]
        
    
    def __process_query_client2resover(self,pkt,srcip, sport, qname,ts):
        print(f'client -> resolver: {qname}')
        with self.__flows_lock:
            root_key = (srcip, sport, qname)
            self.__flows[root_key] = {
                "client": f"{srcip}:{sport}",
                "qname": qname,
                "domains": {qname},
                "counts": defaultdict(int),
                "start": ts,
                "last_update": ts,
            }
            self.__domain2flows[qname].add(root_key)
            self.__delay_queue.put(root_key, ts + self.__timeout_ns)
    
    def __process_query_resolver2upstream(self,qname,ts):
        # 先只处理 _. 开头的查询
        print(f'resolver -> upstream: {qname}')
        with self.__flows_lock:
            if qname.startswith("_."):
                # 获取后缀
                suffix = qname[2:]
                if suffix:
                    # 获取所有匹配该后缀的流
                    match_flow_keys = {flow_key for flow_key in self.__flows.keys() if flow_key[2].endswith(suffix)}
                    self.__add_domains_to_flows_with_lock(flow_keys=list(match_flow_keys),domains=[qname])
                    self.__update_flows(flow_keys=list(match_flow_keys),ts=ts)
    
    def __process_response_resover2client(self,pkt,dns,dstip, dport, qname,ts):
        print(f'resolver -> client: {qname}')
        with self.__flows_lock:
            flow_key = (dstip,dport,qname)
            if flow_key not in self.__flows:
                return
            relate_names = {qname}
            for i in range(getattr(dns, "ancount", 0)):
                relate_names |= set(extract_from_answer(dns.an[i]))
            for i in range(getattr(dns, "nscount", 0)):
                relate_names |= set(extract_from_answer(dns.ns[i]))
            for i in range(getattr(dns, "arcount", 0)):
                relate_names |= set(extract_from_additional(dns.ar[i]))
            self.__add_domains_to_flows_with_lock([flow_key],list(relate_names))
            self.__increase_domains_count([flow_key],list(relate_names))
            self.__update_flows([flow_key],ts)
            self.__finalize_flow(flow_key)
            
                
    def __process_response_upstream2resover(self,pkt,dns,qname,ts):
        print(f'upstream -> resolver: {qname}')
        with self.__flows_lock:
            flow_keys = self.__domain2flows.get(qname, [])
            # 没有找到相关联的流，则尝试推断
            if not flow_keys:
                flow_keys = self.__infer_flows_by_domain(qname)
            if not flow_keys:
                return
            relate_names = {qname}
            for i in range(getattr(dns, "ancount", 0)):
                relate_names |= set(extract_from_answer(dns.an[i]))
            for i in range(getattr(dns, "nscount", 0)):
                relate_names |= set(extract_from_answer(dns.ns[i]))
            for i in range(getattr(dns, "arcount", 0)):
                relate_names |= set(extract_from_additional(dns.ar[i]))
            print(f'relate_names: {relate_names}')
            self.__add_domains_to_flows_with_lock(list(flow_keys), list(relate_names))
            self.__increase_domains_count(list(flow_keys),list(relate_names))
            self.__update_flows(list(flow_keys), ts)
                
    def __process_dns_message(self, pkt, dns, srcip, dstip, sport, dport, ts):
        qname = None
        if getattr(dns, "qd", None):
            qname = norm_domain(dns.qd.qname)
        if qname is None:
            return
        if dns.qr == 0:
            # 这是一个查询包
            if dstip == self.__local_ip and getattr(dns, "rd", 0) == 1:
                # 客户端 -> 解析器：创建流
                self.__process_query_client2resover(pkt=pkt,srcip=srcip,sport=sport,qname=qname,ts=ts)
            if srcip == self.__local_ip and getattr(dns, "rd", 0) == 0:
                # 解析器 -> 权威服务器：绑定流
                self.__process_query_resolver2upstream(qname=qname,ts=ts)
        if dns.qr == 1:
            if srcip == self.__local_ip:
                self.__process_response_resover2client(pkt=pkt,dns=dns,dstip=dstip,dport=dport,qname=qname,ts=ts)
            if dstip == self.__local_ip:
                self.__process_response_upstream2resover(pkt=pkt,dns=dns,qname=qname,ts=ts)

    def __trim_segments_before_next(self, stream):
        """
        将所有起始序号小于 next_seq 的段裁剪到 next_seq（保留尾部）
        """
        next_seq = stream["next_seq"]
        segments = stream["segments"]
        for s in list(segments.keys()):
            if s >= next_seq:
                continue
            buf = segments.pop(s)
            overlap = next_seq - s
            if overlap >= len(buf):
                continue
            tail = buf[overlap:]
            exist = segments.get(next_seq)
            if exist is None or len(tail) > len(exist):
                segments[next_seq] = tail

    def __store_tcp_segment(self, stream, seq, data):
        """
        保存 TCP 段，处理与已存段的重叠，尽量保留最长连续数据。
        """
        if not data:
            return
        next_seq = stream["next_seq"]
        if seq < next_seq:
            overlap = next_seq - seq
            if overlap >= len(data):
                return
            data = data[overlap:]
            seq = next_seq

        segments = stream["segments"]
        start = seq
        end = seq + len(data)
        for s in list(segments.keys()):
            buf = segments[s]
            e = s + len(buf)
            if e <= start or s >= end:
                continue
            segments.pop(s)
            if s < start:
                prefix = buf[: start - s]
                if prefix:
                    segments[s] = prefix
            if e > end:
                tail = buf[end - s:]
                if tail:
                    segments[end] = tail

        segments[seq] = data

    def __extract_tcp_dns_messages(self, pkt, ts):
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            return []
        srcip, dstip = get_ip_tuple(pkt)
        sport, dport = get_l4_ports(pkt)
        if srcip is None or dstip is None:
            return []
        key = (srcip, sport, dstip, dport)
        stream = self.__tcp_streams.get(key)
        if stream is None:
            stream = {
                "next_seq": tcp.seq,
                "segments": {},
                "buffer": b"",
                "last_ts": ts,
            }
            self.__tcp_streams[key] = stream
        stream["last_ts"] = ts

        seq = tcp.seq
        data = payload
        if seq < stream["next_seq"]:
            overlap = stream["next_seq"] - seq
            if overlap >= len(data):
                return []
            data = data[overlap:]
            seq = stream["next_seq"]

        if data:
            self.__store_tcp_segment(stream, seq, data)

        assembled = b""
        while True:
            self.__trim_segments_before_next(stream)
            chunk = stream["segments"].pop(stream["next_seq"], None)
            if chunk is None:
                break
            assembled += chunk
            stream["next_seq"] += len(chunk)

        if assembled:
            stream["buffer"] += assembled
            if len(stream["buffer"]) > self.__tcp_stream_max_buffer:
                stream["buffer"] = stream["buffer"][-self.__tcp_stream_max_buffer:]

        messages = []
        buf = stream["buffer"]
        offset = 0
        while len(buf) - offset >= 2:
            msg_len = int.from_bytes(buf[offset:offset + 2], "big")
            if len(buf) - offset < 2 + msg_len:
                break
            start = offset + 2
            end = start + msg_len
            messages.append(buf[start:end])
            offset = end
        if offset:
            stream["buffer"] = buf[offset:]

        if tcp.flags & 0x05:  # FIN or RST
            self.__tcp_streams.pop(key, None)

        return messages

    def __process_packet(self, pkt):
        ts = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        srcip, dstip = get_ip_tuple(pkt)
        if srcip is None or dstip is None:
            return
        sport, dport = get_l4_ports(pkt)

        if pkt.haslayer(UDP):
            if not pkt.haslayer(DNS):
                return
            dns = pkt[DNS]
            print(f'pkt {self.__pkt_index} | UDP |',end='')
            self.__pkt_index += 1
            self.__process_dns_message(pkt=pkt,dns=dns,srcip=srcip,dstip=dstip,sport=sport,dport=dport,ts=ts)
            return

        if pkt.haslayer(TCP):
            for dns_bytes in self.__extract_tcp_dns_messages(pkt=pkt, ts=ts):
                try:
                    dns = DNS(dns_bytes)
                except Exception as e:
                    continue
                print(f'pkt {self.__pkt_index} | TCP |',end='')
                self.__pkt_index += 1
                self.__process_dns_message(pkt=pkt,dns=dns,srcip=srcip,dstip=dstip,sport=sport,dport=dport,ts=ts)
