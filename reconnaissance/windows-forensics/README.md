# Windows Forensics

Windows Forensics is the method of gathering information about the target Windows system.

### System Information <a href="#system-information" id="system-information"></a>

#### IP Address & MAC Address <a href="#ip-address-mac-address" id="ip-address-mac-address"></a>

Below are the location of the file which contains the information of IP address and MAC address.

```
# Look@LAN is a network monitoring tool. So if the system uses the tool, we can retrieve the information of the network.
# LANIP -> IP address
# LANNIC -> MAC address
c:\Program Files (x86)\Look@LAN\irunin.ini
```

#### Network Cards <a href="#network-cards" id="network-cards"></a>

The name of the network card is such like “Intel(R) PRO/1000 MT Desktop Adapter”.

```
c:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2023_1_2_3_45_67.etl
```

#### PowerShell History <a href="#powershell-history" id="powershell-history"></a>

Sometimes PowerShell command history contains the sensitive information about the system.

```
c:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

#### Malware History <a href="#malware-history" id="malware-history"></a>

Suspicious activities are likely detected by Windows Defender.

```
c:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\
```

### Event Logs <a href="#event-logs" id="event-logs"></a>

#### Event Viewer <a href="#event-viewer" id="event-viewer"></a>

Below is the list of item worth noting.

* **`Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`**
* **`Applications and Services Logs/Microsoft/Windows/PrintService/Admin`**

In each item, we can find the desired list by specifying the keyword in the “Find” action in the right pane.

#### PowerShell <a href="#powershell" id="powershell"></a>

Also we can see event logs from a logfile in PowerShell.

```
Get-WinEvent -Path  .\Example.evtx -FilterXPath '*/System/*' | Sort-Object TimeCreated
```

### Processes <a href="#processes" id="processes"></a>

#### Process Monitor <a href="#process-monitor" id="process-monitor"></a>

* To get the parent PID of the specific process, click **“Filter”** icon and enter the process name (e.g. “spoolsv.exe”) then select **“Include”**, and click Apply. Right-click on the highlighted item and go to **“Process”** tab. We can see the parent PID.

### Registry Hives <a href="#registry-hives" id="registry-hives"></a>

A hive is a logical group of keys, subkeys, and values in the registry that has a set of supporting files loaded into memory when the operating system is started or a user logs in.

#### Registry Editor <a href="#registry-editor" id="registry-editor"></a>

We can find registry keys in the Registry Editor.

1. Click on the Windows icon and select Run.
2. Enter “regedit” in the input form. Registry Editor opens.

#### File Locations <a href="#file-locations" id="file-locations"></a>

**Registry Hives** are located in C:\Windows\System32\config.

* **DEFAULT (HKEY\_USERS\DEFAULT in regedit)**
* **SAM (HKEY\_LOCAL\_MACHINE\SAM in regedit)**
* **SECURITY (HKEY\_LOCAL\_MACHINE\Security in regedit)**
* **SOFTWARE (HKEY\_LOCAL\_MACHINE\Software in regedit)**
* **SYSTEM (HKEY\_LOCAL\_MACHINE\System in regedit)**

The other hives are located in user home directory (C:\Users\\\<username>)

*   **NTUSER.DAT (HKEY\_CURRENT\_USER in regedit)**

    It contains the information of the user account settings.\
    It is located in **C:\Users\\\<username>** .
*   **USRCLASS.DAT (HKEY\_CURRENT\_USER\Software\CLASSES)**

    It stores the ShellBag information for the Desktop, ZIP files, remote folders, local folders, etc.\
    It is located in **C:\Users\\\<username>\AppData\Local\Microsoft\Windows** .

**Amcache Hive** is located in **C:\Windows\AppCompat\Programs\Amcache.hve** .\
It stores the information on programs that were recently run on the system.

### Acquire Registry Data <a href="#acquire-registry-data" id="acquire-registry-data"></a>

* **KAPE**
* [**Autopsy**](https://www.autopsy.com/)
* [**FTK Imager**](https://www.exterro.com/ftk-imager)

<br>

### Gather Information From Registry Hives <a href="#gather-information-from-registry-hives" id="gather-information-from-registry-hives"></a>

We can retrieve information using [Registry Viewer](https://accessdata.com/product-download/registry-viewer-2-0-0) or [Registry Explorer](https://ericzimmerman.github.io/#!index.md).

#### OS Version <a href="#os-version" id="os-version"></a>

* SOFTWARE\Microsoft\Windows NT\CurrentVersion)

#### Current Control Set <a href="#current-control-set" id="current-control-set"></a>

* SYSTEM\ControlSet001
* SYSTEM\ControlSet002

#### Computer Name <a href="#computer-name" id="computer-name"></a>

* SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName

#### Time Zone <a href="#time-zone" id="time-zone"></a>

* SYSTEM\CurrentControlSet\Control\TimeZoneInformation

#### Network <a href="#network" id="network"></a>

* SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces

#### SAM Hive & User Information <a href="#sam-hive-user-information" id="sam-hive-user-information"></a>

* SAM\Domains\Account\Users

#### Recent Files <a href="#recent-files" id="recent-files"></a>

* NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explore\RecentDocs

#### Microsoft Office Recent Files <a href="#microsoft-office-recent-files" id="microsoft-office-recent-files"></a>

* NTUSER.DAT\Software\Microsoft\Office\VERSION

#### ShellBags <a href="#shellbags" id="shellbags"></a>

* USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bag
* USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
* NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
* NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags

#### ShimCache <a href="#shimcache" id="shimcache"></a>

* SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

#### AmCache <a href="#amcache" id="amcache"></a>

* Amcache.hve\Root\File\\\<Volume GUID>\\

#### BAM/DAM <a href="#bamdam" id="bamdam"></a>

* SYSTEM\CurrentControlSet\Services\bam\UserSettings\\\<SID>
* SYSTEM\CurrentControlSet\Services\dam\UserSetitngs\\\<SID>

#### UserAssist <a href="#userassist" id="userassist"></a>

* NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\\\<GUID>\Count

#### Devices <a href="#devices" id="devices"></a>

* SYSTEM\CurrentControlSet\Enum\USBSTOR
* SYSTEM\CurrentControlSet\Enum\USB
* SOFTWARE\Microsoft\Windows Portable Devices\Devices

### References <a href="#references" id="references"></a>

* [TryHackMe](https://tryhackme.com/room/windowsforensics1)
