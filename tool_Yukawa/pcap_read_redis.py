import json
import redis
from redis.exceptions import ConnectionError
import os
import time

def main():
    # 连接 Redis
    try:
        r = redis.Redis(host='localhost', port=6379, db=0, socket_connect_timeout=2)
        r.ping()
        print("✅ Successfully connected to Redis server")
    except ConnectionError:
        print("❌ Cannot connect to Redis. Is the service running?")
        print("Try: sudo systemctl restart redis-server")
        return
    
    # 检查文件
    filename = "result_baidu_duobao1.json"
    if not os.path.exists(filename):
        print(f"❌ Error: {filename} file not found in current directory")
        print(f"Current working directory: {os.getcwd()}")
        print("💡 Place your JSON file in this directory or update the filename in the script")
        return
    
    # 清空现有数据
    queue_name = 'dns_analysis_results'
    r.delete(queue_name)
    print(f"🧹 Cleared existing data from {queue_name} list")
    
    # 读取并推送 JSON 数据
    try:
        start_time = time.time()
        pushed_count = 0
        
        print(f"🔍 Reading {filename}...")
        with open(filename, 'r') as f:
            try:
                # 正确处理 JSON 数组格式
                data = json.load(f)
                
                # 确保是列表格式
                if not isinstance(data, list):
                    print("⚠️ Warning: JSON is not an array, wrapping in list")
                    data = [data]
                
                total_records = len(data)
                print(f"📦 Found {total_records} DNS analysis records in JSON array")
                
                # 推送到 Redis
                for i, record in enumerate(data, 1):
                    # 验证是否为字典
                    if not isinstance(record, dict):
                        print(f"⚠️  Record #{i} is not a dictionary, skipping")
                        continue
                    
                    # 验证必要字段
                    if 'client' not in record or 'qname' not in record:
                        print(f"⚠️  Record #{i} missing required fields, skipping")
                        continue
                    
                    # 推送到 Redis
                    r.rpush(queue_name, json.dumps(record))
                    pushed_count += 1
                    
                    # 显示进度
                    if i % 5 == 0 or i == total_records:
                        progress = f"{i}/{total_records}"
                        print(f"✅ Pushed {progress} records...")
                    
                    # 显示前3条详情
                    if i <= 3:
                        client = record['client']
                        qname = record['qname']
                        print(f"   ↪️ Record {i}: {client} queried {qname}")
            
            except json.JSONDecodeError as e:
                print(f"❌ JSON decode error: {e}")
                print(f"File position: line {e.lineno}, column {e.colno}")
                print("Your file must be a valid JSON array format ([{...}, {...}])")
                return
        
        # 完成统计
        elapsed = time.time() - start_time
        print(f"\n🎉 Success! Pushed {pushed_count} records to Redis in {elapsed:.2f} seconds")
        print(f"📊 Rate: {pushed_count/elapsed:.1f} records/second")
        print(f"📌 Data is now available in Redis list: '{queue_name}'")
        print(f"💡 Run consumer with: python json_consumer.py")
    
    except Exception as e:
        print(f"❌ Error processing file: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
