import argparse
import csv
import json
import os
import threading
import time
import redis
from collections import defaultdict
import numpy as np
import pcap_pre_live
from tail_detector import load_tail_detector

# 超参数：特征向量长度
X = 157  # 可根据实际需求调整
feature_len = 10  # 特征长度


class DNSPreprocessor:
    def __init__(self, export_dataset=False, default_score=0):
        # 共享数据结构 (线程安全)
        self.lock = threading.Lock()
        
        # Mapr: recursive_domain -> {qname: count}
        self.Mapr = defaultdict(lambda: defaultdict(int))
        
        # Mapq: (client, qname, start_time, end_time) -> [feature vector]
        self.Mapq = {}
        
        # KeyToDomains: (client, qname, start_time, end_time) -> [recursive_domains]
        self.KeyToDomains = {}
        
        # QnameToKeys: qname -> set(keys)
        self.QnameToKeys = defaultdict(set)
        
        # Redis连接
        self.redis1 = redis.Redis()
        self.redis2 = redis.Redis()
        
        # 队列名称
        self.queue1 = 'dns_analysis_results'
        self.queue2 = 'dns_events'

        self.export_dataset = export_dataset
        self.default_score = default_score
        self.dataset_file = None
        self.dataset_writer = None
        if self.export_dataset:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"dataset_{timestamp}.csv"
            output_path = os.path.join(os.path.dirname(__file__), filename)
            self.dataset_file = open(output_path, "w", newline="", encoding="utf-8")
            self.dataset_writer = csv.writer(self.dataset_file)
            header = ["Domain", "score", "total_count"] + [f"x{i}" for i in range(X)]
            self.dataset_writer.writerow(header)
            print(f"Dataset export enabled: {output_path}")
        else:
            # 加载TailDetector模型（替换原来的AnomalyDetectionPipeline）
            self.anomaly_detector = load_tail_detector("models/detector.pkl")
            print(f"Model loaded successfully! Expected feature count: {len(self.anomaly_detector.feature_cols_)}")

    def thread1_processor(self):  # 通过分析dns响应获取的递归域名信息
        """线程1：处理dns_analysis_results队列"""
        while True:
            result = self.redis1.blpop(self.queue1, timeout=0)
            if result is None:
                continue
            
            _, message_bytes = result
            try:
                record = json.loads(message_bytes.decode('utf-8'))
                client = record.get('client', '')
                qname = record.get('qname', '')
                recursive_domains = record.get('recursive_domains', [])
                start_time = record.get('start_time')
                end_time = record.get('end_time')  # 可能为 None
                
                # 生成唯一Key (client, qname, start_time, end_time)
                key = (client, qname, start_time, end_time)
                
                # 线程安全操作共享数据
                with self.lock:
                    # 1. 更新Mapr (递归域名映射)
                    for domain in recursive_domains:
                        self.Mapr[domain][qname] += 1
                    
                    # 2. 初始化Mapq (特征向量)
                    if key not in self.Mapq:
                        self.Mapq[key] = [0] * X
                    
                    # 3. 记录Key关联的域名
                    self.KeyToDomains[key] = recursive_domains
                    
                    # 4. 更新Qname到Key的映射
                    self.QnameToKeys[qname].add(key)
                    
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                print(f"线程1解析错误: {e}")

    def thread2_processor(self):  # 基于ebpf获取的hook信息
        """线程2：处理dns_events队列 (延迟10秒启动)"""
        time.sleep(6)  # 等待6秒再启动（根据您的需求调整）
        print("start processing dns_events queue...")
        while True:
            result = self.redis2.blpop(self.queue2, timeout=0)
            if result is None:
                continue
            
            _, message_bytes = result
            try:
                record = json.loads(message_bytes.decode('utf-8'))
                timestamp_boot_ns = record.get('Timestamp_boot_ns')
                recursive_domain = record.get('recursive_domain', '')
                hook_id = record.get('Hook_id')
                # 确保关键字段存在
                if timestamp_boot_ns is None or hook_id is None:
                    continue
                
                # 线程安全操作共享数据
                with self.lock:
                    # 步骤1: 清理过期Key (end_time < timestamp_boot_ns)
                    keys_to_remove = []
                    for key, feature_vec in list(self.Mapq.items()):
                        _, _, _, end_time = key
                        # 修复点：跳过 end_time 为 None 的情况
                        if end_time is not None and end_time < timestamp_boot_ns:
                            keys_to_remove.append(key)
                    
                    # 处理需要清理的Key
                    for key in keys_to_remove:
                        # 1. 输出特征向量
                        print(f"输出特征向量 for {key}: {self.Mapq[key]}")
                        client, qname, start_time, end_time = key
                        # --- 开始：模型推理与结果输出 ---
                        
                        
                        # 修复：将列表转换为numpy数组
                        feature_array = np.array(self.Mapq[key])
                        print(f"Feature vector: {feature_array.tolist()}")  # 为了显示与原来相同的格式
                        feature_array = np.array(self.Mapq[key], dtype=float)  # 确保是浮点类型
                        total = np.sum(feature_array)
                        if total > 0:
                            normalized_array = feature_array / total
                        else:
                            normalized_array = feature_array  # 处理全零向量的情况
                        if self.export_dataset:
                            domain = qname
                            score = self.default_score
                            row = [domain, score, float(total)] + normalized_array.tolist()
                            self.dataset_writer.writerow(row)
                        else:
                            try:
                                # 调用模型预测（使用新的predict_single方法）
                                print(f"\nProcessing expired key: {normalized_array}")
                                prediction, score = self.anomaly_detector.predict_single(normalized_array)

                                # 输出结果（完全匹配原始脚本格式）
                                print(f"\n>>> Prediction Result for key: {key}")
                                print(f"- Anomaly Score: {score:.4f}")
                                print(f"- Threshold: {self.anomaly_detector.get_threshold():.4f}")
                                print(f"- Classification: {'Malicious (Anomaly)' if prediction == 1 else 'Benign (Normal)'}")

                            except Exception as e:
                                print(f"❌ Model prediction failed for key {key}: {e}")
                        
                        # --- 结束：模型推理 ---
                        
                        # 2. 清理Mapr引用
                        client, qname, start_time, end_time = key
                        for domain in self.KeyToDomains.get(key, []):
                            if qname in self.Mapr[domain]:
                                self.Mapr[domain][qname] -= 1
                                if self.Mapr[domain][qname] == 0:
                                    del self.Mapr[domain][qname]
                        
                        # 3. 从其他数据结构中移除
                        if key in self.Mapq:
                            del self.Mapq[key]
                        if key in self.KeyToDomains:
                            del self.KeyToDomains[key]
                        if qname in self.QnameToKeys:
                            self.QnameToKeys[qname].discard(key)
                    
                    # 步骤2: 处理当前递归域名事件
                    if recursive_domain and recursive_domain in self.Mapr:
                        for qname in list(self.Mapr[recursive_domain].keys()):
                            # 遍历所有引用该qname的Key
                            for key in list(self.QnameToKeys.get(qname, set())):
                                # 确保Key仍然有效
                                if key in self.Mapq and hook_id < X:
                                    self.Mapq[key][hook_id] += 1
            
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                print(f"线程2解析错误: {e}")

    def start(self):
        """启动双线程处理"""
        t1 = threading.Thread(target=self.thread1_processor, daemon=True)
        t2 = threading.Thread(target=self.thread2_processor, daemon=True)
        
        t1.start()
        t2.start()
        print("预处理系统已启动...")
        
        # 保持主线程运行
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n系统已停止")
        finally:
            if self.dataset_file:
                self.dataset_file.flush()
                self.dataset_file.close()

def main():
    parser = argparse.ArgumentParser(description="Start DNS preprocessor with live pcap capture")
    parser.add_argument("-i", "--iface", required=True, help="Interface name for live capture")
    parser.add_argument("--export-dataset", action="store_true", help="Export dataset CSV instead of model inference")
    parser.add_argument("--default-score", type=float, default=0, help="Default score when exporting dataset")
    args = parser.parse_args()

    if not pcap_pre_live.setup_live_capture(args.iface):
        return

    pcap_thread = threading.Thread(
        target=pcap_pre_live.parse_live,
        args=(args.iface,),
        daemon=True,
    )
    pcap_thread.start()

    processor = DNSPreprocessor(
        export_dataset=args.export_dataset,
        default_score=args.default_score,
    )
    processor.start()


if __name__ == "__main__":
    main()
