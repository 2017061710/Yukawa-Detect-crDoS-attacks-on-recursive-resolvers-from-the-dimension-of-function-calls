import redis
import threading
import json
from traffic_analyzer import DNSTrafficAnalyzer
from collections import defaultdict
from utils import *
from timed_heap import TimedHeap
import numpy as np
import time
import csv
import os
from tail_detector import load_tail_detector


class Yukawa:
    def __init__(self, feature_dim = 157 ,export_dataset=False, default_score=0):
        # 用于获取hook信息
        self.__redis = redis.Redis()
        self.__hook_key = 'dns_events'
        
        # qname -> ts
        self.__discard_event = {}
        self.__export_dataset = export_dataset
        self.__default_score = default_score
        self.__feature_dim = feature_dim
        self.__dns_traffic_analyzer = DNSTrafficAnalyzer()
        self.dataset_file = None
        self.dataset_writer = None
        if self.__export_dataset:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"dataset_{timestamp}.csv"
            output_path = os.path.join(os.path.dirname(__file__), filename)
            self.dataset_file = open(output_path, "w", newline="", encoding="utf-8")
            self.dataset_writer = csv.writer(self.dataset_file)
            header = ["Domain", "score", "total_count"] + [f"x{i}" for i in range(self.__feature_dim)]
            self.dataset_writer.writerow(header)
            self.dataset_file.flush()
            print(f"Dataset export enabled: {output_path}")
        else:
            # 加载TailDetector模型（替换原来的AnomalyDetectionPipeline）
            self.anomaly_detector = load_tail_detector("models/detector.pkl")
            print(f"Model loaded successfully! Expected feature count: {len(self.anomaly_detector.feature_cols_)}")
        
        self.__query_lock = threading.Lock()
        self.__query2features = {}
        self.__query_timed_heap = TimedHeap()
        self.__domain2qname = defaultdict(lambda: defaultdict(int))
        self.__query2domains = {}
        self.__qname2query = defaultdict(set)
        
    def __process_dns_events(self):
        # 首先清空redis中的dns_events
        self.__redis.delete(self.__hook_key)
        while True:
            event = self.__redis.blpop([self.__hook_key],timeout=1)
            if event is None:
                with self.__query_lock:
                    timestamp_boot_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                    self.__process_expired_query_with_lock(timestamp_boot_ns)
                continue
            _, message_bytes = event
            try:
                record = json.loads(message_bytes.decode('utf-8'))
                timestamp_boot_ns = record.get('Timestamp_boot_ns')
                recursive_domain = norm_domain(record.get('recursive_domain', ''))
                hook_id = record.get('Hook_id')
                if timestamp_boot_ns is None or hook_id is None:
                    continue
                with self.__query_lock:
                    self.__process_expired_query_with_lock(timestamp_boot_ns)

                max_retries = 10
                found = False
                for _ in range(max_retries):
                    with self.__query_lock:
                        if recursive_domain in self.__domain2qname:
                            found = True
                            for qname in self.__domain2qname[recursive_domain]:
                                if qname in self.__qname2query and hook_id < self.__feature_dim:
                                    for query_key in self.__qname2query[qname]:
                                        self.__query2features[query_key][hook_id] += 1
                            break
                    if not found:
                        if recursive_domain in self.__discard_event and (timestamp_boot_ns - self.__discard_event[recursive_domain]) < 5_000_000_000:
                            break
                        time.sleep(1)
                        print(f"第{_}次等待域名: '{recursive_domain}'")
                if not found:
                    print(f"放弃域名: {recursive_domain}")
                    self.__discard_event[recursive_domain] = timestamp_boot_ns
                            
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                print(f"线程2解析错误: {e}")
    
    def __process_dns_traffic(self):
        while True:
            report = self.__dns_traffic_analyzer.get_report()
            print(f"report:{report}")
            client = report.get('client','')
            qname = report.get('qname','')
            recursive_domains = report.get('recursive_domains',[])
            start_time = report.get('start_time',0)
            end_time = report.get('end_time',0)
            
            query_key = (client,qname,start_time,end_time)
            with self.__query_lock:
                for domain in recursive_domains:
                    if not domain:
                        continue
                    self.__domain2qname[domain][qname] += 1
                if query_key not in self.__query2features:
                    self.__query2features[query_key] = [0]*self.__feature_dim
                
                self.__query2domains[query_key] = recursive_domains
                self.__qname2query[qname].add(query_key)
                self.__query_timed_heap.add(query_key, end_time)
        
    
    def __process_expired_query_with_lock(self,timestamp_boot_ns):
        """
        注意：这个函数必须使用锁保护
        """
        expired_queries = self.__query_timed_heap.get_older_than(timestamp_boot_ns)
        for query_key in expired_queries:
            client, qname, start_time, end_time = query_key
            print(f"Processing expired key: {query_key} with end_time = {end_time} < {timestamp_boot_ns}")
            print(f"features for {query_key}: {self.__query2features[query_key]}")
            print(f"total count: {np.sum(self.__query2features[query_key])}")
            feature_array = np.array(self.__query2features[query_key], dtype=float)
            total = float(np.sum(feature_array))
            if total > 0:
                normalized_array = feature_array / total
            else:
                normalized_array = feature_array  # 处理全零向量
            
            if self.__export_dataset:
                domain = qname
                score = self.__default_score
                row = [domain, score, total] + normalized_array.tolist()
                self.dataset_writer.writerow(row)
                self.dataset_file.flush()
            else:
                try:
                    print(f"Processing expired key: {normalized_array}")
                    prediction, score = self.anomaly_detector.predict_single(normalized_array)

                    print(f">>> Prediction Result for key: {query_key}")
                    print(f"- Anomaly Score: {score:.4f}")
                    print(f"- Threshold: {self.anomaly_detector.get_threshold():.4f}")
                    print(f"- Classification: {'Malicious (Anomaly)' if prediction == 1 else 'Benign (Normal)'}")
                except Exception as e:
                    print(f"❌ Model prediction failed for key {query_key}: {e}")
            for domain in self.__query2domains[query_key]:
                if domain in self.__domain2qname and qname in self.__domain2qname[domain]:
                    self.__domain2qname[domain][qname] -= 1
                    if self.__domain2qname[domain][qname] == 0:
                        del self.__domain2qname[domain][qname]
                        if not self.__domain2qname[domain]:
                            del self.__domain2qname[domain]
            del self.__query2features[query_key]
            del self.__query2domains[query_key]
            if qname in self.__qname2query:
                self.__qname2query[qname].remove(query_key)
                if not self.__qname2query[qname]:
                    del self.__qname2query[qname]
        
    def cleanup(self):
        """清理资源，确保数据集文件被正确关闭和写入"""
        print("\n--- Received interrupt signal, cleaning up... ---")
        if self.dataset_file and not self.dataset_file.closed:
            print("Flushing and closing dataset file...")
            self.dataset_file.flush() # 强制将缓冲区内容写入磁盘
            self.dataset_file.close()
            print("Dataset file closed.")
        else:
            print("No dataset file to close or it was already closed.")
    def start(self,iface):
        # 启动两个线程，一个用于处理DNS流量，一个用于处理Hook信息
        threading.Thread(target=self.__process_dns_traffic).start()
        threading.Thread(target=self.__process_dns_events).start()
        # 最后启动DNS流量分析器，保持阻塞
        try:
            self.__dns_traffic_analyzer.listen(iface)
        except KeyboardInterrupt:
            self.cleanup()
    
if __name__ == '__main__':
    yukawa = Yukawa(export_dataset=True)
    yukawa.start('eth0')