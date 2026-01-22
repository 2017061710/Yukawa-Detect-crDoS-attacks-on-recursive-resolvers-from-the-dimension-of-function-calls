import re
import json
import redis
from redis.exceptions import ConnectionError

# 连接 Redis
try:
    r = redis.Redis(host='localhost', port=6379, db=0, socket_connect_timeout=2)
    r.ping()
    print("✅ Successfully connected to Redis server")
except ConnectionError:
    print("❌ Cannot connect to Redis. Is the service running?")
    print("Try: sudo systemctl restart redis-server")
    exit(1)

def parse_log_content(content):
    """解析多行日志内容，返回事件列表"""
    # 匹配完整的 DetailFuncEvent 块（支持跨行）
    pattern = re.compile(
        r'received:DetailFuncEvent\{[\s\S]*?\}',
        re.MULTILINE
    )
    
    events = []
    for match in pattern.finditer(content):
        event_str = match.group(0)
        
        # 提取字段的详细正则
        field_pattern = re.compile(
            r'Timestamp_boot_ns:\s*(\d+),\s*'
            r'Tgid_pid:\s*(\d+),\s*'
            r'Hook_id:\s*(\d+)\s*\(([^)]+)\),\s*'
            r'recursive_domain:\s*([^,]+),\s*'
            r'Type:\s*(\d+),\s*'
            r'Transaction_id:\s*(\d+)'
        )
        
        fields_match = field_pattern.search(event_str)
        if not fields_match:
            print(f"⚠️ 无法解析事件: {event_str[:100]}...")
            continue
            
        fields = fields_match.groups()
        events.append({
            "Timestamp_boot_ns": int(fields[0]),
            "Tgid_pid": int(fields[1]),
            "Hook_id": int(fields[2]),
            "Hook_name": fields[3].strip(),
            "recursive_domain": fields[4].strip(),
            "Type": int(fields[5]),
            "Transaction_id": int(fields[6])
        })
    
    return events

def main():
    # 清空现有数据（可选）
    r.delete('dns_events')
    print("🧹 Cleared existing data from dns_events list")
    
    # 读取整个文件内容（处理跨行记录）
    try:
        with open('events.log', 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print("❌ Error: events.log file not found in current directory")
        print("Current path:", __file__)
        return
    
    # 解析日志
    print("🔍 Parsing log file...")
    events = parse_log_content(content)
    
    # 推送到 Redis
    for i, event in enumerate(events, 1):
        r.rpush('dns_events', json.dumps(event))
        print(f"✅ Event {i}: Pushed {event['recursive_domain']} (TXID: {event['Transaction_id']})")
    
    print(f"\n🎉 Success! Pushed {len(events)} events to Redis")

if __name__ == '__main__':
    main()
