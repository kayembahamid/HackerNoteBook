# OpenVPN Troubleshooting

### Set Correct MTU (Maximum Transmission Unit) <a href="#set-correct-mtu-maximum-transmission-unit" id="set-correct-mtu-maximum-transmission-unit"></a>

#### 1. Get correct MTU <a href="#id-1-get-correct-mtu" id="id-1-get-correct-mtu"></a>

Start Ping at the 1500 mtu and decrease the 1500 value by 10 each time.\
On Linux,

```shellscript
# -M: mtu discovery
# -s: data size
ping -M do -s 1500 -c 1 <target-ip>

# if the packet loss, 
ping -M do -s 1490 -c 1 <target-ip>

# if the packet loss yet,
ping -M do -s 1480 -c 1 <target-ip>

# if packet loss yet,
ping -M do -s 1470 -c 1 <target-ip>

# continue until packet is received...
```

#### 2. Get correct MSS (Maximum Segment Size) <a href="#id-2-get-correct-mss-maximum-segment-size" id="id-2-get-correct-mss-maximum-segment-size"></a>

After you find the correct MTU, now you need to get the MSS from the MTU.\
To get the correct one, subtract 40 from the value of the MTU.

```shellscript
mss = mtu - 40
```

For example, if you get 1470 value of the MTU in the previous `ping` section, the MSS is 1430.

#### 3. Set correct MSS into the config file of OpenVPN <a href="#id-3-set-correct-mss-into-the-config-file-of-openvpn" id="id-3-set-correct-mss-into-the-config-file-of-openvpn"></a>

Set **mssfix** in the configuration file (.ovpn) of the OpenVPN.

```shellscript
mssfix 1430
```

Replace the 1430 value with the value you found.

### Data Cipher Errors <a href="#data-cipher-errors" id="data-cipher-errors"></a>

If you got the error such as **"ERROR: failed to negotiate cipher with server. Add the server's cipher ('AES-256-CBC') to --data-ciphers (currently 'AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305') if you want to connect to this server."** when starting **`openvpn`** with the **`.ovpn`** config file, it may be helpful to add the following line to the **`.ovpn`** file for fixing this error.

```shellscript
# example.ovpn

data-ciphers AES-256-CBC
```
