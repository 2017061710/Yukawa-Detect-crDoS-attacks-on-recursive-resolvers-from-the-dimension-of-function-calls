# Yukawa-Detect-crDoS-attacks-on-recursive-resolvers-from-the-dimension-of-function-calls

## Install dependencies

```bash
conda create -n yukawa --no-default-packages python=3.11
pip install -r requirements.txt
```

## Start
```bash
cd tool_Yukawa
python main.py -i eth0

cd tool_Yukawa/dns-ebpf
./build/dns-ebpf -mode detail -v -c config/bind/9_16_2/detail.yaml -e -event-targets redis


sudo apt install -y redis-server
redis-server --daemonize yes
redis-cli ping

named -c /etc/bind/named.conf          # Run in the background
named -g -c /etc/bind/named.conf       # Run in the foreground
```



## Generate the dataset

```bash
cd tool_Yukawa
python main.py -i eth0 --export-dataset --default-score 0
```

```
dig @172.17.0.2 KeySigTrap.example.top
```
