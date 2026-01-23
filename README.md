# Yukawa-Detect-crDoS-attacks-on-recursive-resolvers-from-the-dimension-of-function-calls

## 依赖安装

```bash
conda create -n yukawa --no-default-packages python=3.11
pip install -r requirements.txt
```

## 使用
```bash
cd tool_Yukawa
python main.py -i eth0

cd tool_Yukawa/dns-ebpf
./build/dns-ebpf -mode detail -v -c config/bind/9_16_2/detail.yaml -e -event-targets redis
```