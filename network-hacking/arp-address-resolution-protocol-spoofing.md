# ARP (Address Resolution Protocol) Spoofing

## ARP (Address Resolution Protocol) Spoofing <a href="#arp-address-resolution-protocol-spoofing" id="arp-address-resolution-protocol-spoofing"></a>

ARP is used to find another computer’s MAC address based on its IP address.

### Basic Flow <a href="#basic-flow" id="basic-flow"></a>

1.  **Check Interface and Gateway IP Address**

    ```shellscript
    # Interfaces
    ip addr

    # Default gateway
    ip route list
    ```
2.  **Scan the Network to Find Target IP**

    ```shellscript
    nmap -sP <gateway-ip>/24
    nmap -sP <gateway-ip>/16
    ```
3.  **Enable IP Forwarding**

    ```shellscript
    # Allow all forwading in the LAN
    # -A: append rules
    # -i: interface
    # -j: jump
    iptables -A FORWARD -i eth0 -j ACCEPT
    ```

### Find MAC Address <a href="#find-mac-address" id="find-mac-address"></a>

```shellscript
cat /sys/class/net/eth0/address
cat /sys/class/net/enp0s3/address
cat /sys/class/net/tun0/address
```
