# Tshark Cheat Sheet

Tshark is a terminal-oriented version of Wireshark. It's a network protocol analyzer.

### Basic Capture <a href="#basic-capture" id="basic-capture"></a>

```shellscript
tshark

# -i: interface (default: eth0)
tshark -i tun0
# --list-interface: List interfaces available
tshark --list-interfaces

# -r: Use a captured file
tshark -r example.pcapng

# Number of packets
tshark -r example.pcapng | wc -l

# Hex dump
tshark -r example.pcapng --hexdump all
```

### Filtering <a href="#filtering" id="filtering"></a>

We can filter packets using `-Y` option.

#### Protocols <a href="#protocols" id="protocols"></a>

```shellscript
# HTTP
tshark -Y 'http'

# ICMP
tshark -Y 'icmp'

# TCP/UDP
tshark -Y 'tcp'
tshark -Y 'udp'
```

#### IP Address <a href="#ip-address" id="ip-address"></a>

```shellscript
tshark -Y 'ip.addr == 127.0.0.1'

# Source address
tshark -Y 'ip.src == 127.0.0.1'

# Destination address
tshark -Y 'ip.dst == 127.0.0.1'
```

### Dump Transferred Data <a href="#dump-transferred-data" id="dump-transferred-data"></a>

```shellscript
tshark -r example.pcapng -T fields -e data -Y "ip.src == 10.0.0.2 and ip.dst == 10.0.0.3" > data.txt
```
