# Firmware Analysis

### Static Analysis <a href="#static-analysis" id="static-analysis"></a>

The following tools are useful for static analysis.

* [**Firmwalker**](https://github.com/craigz28/firmwalker)
* [**firmware-mod-kit**](https://code.google.com/archive/p/firmware-mod-kit/)

```shellscript
file ./firmware

binwalk ./firmware
# -M: Matryosika (recursively) scan extracted files
# -r: Delete carved files after extracting
# -e: Extract known file types
binwalk -Mre ./firmware
# -E: Calculate file entropy
# -N: Do not generate an entropy plot graph
binwalk -EN ./firmware

# firmware-mod-kit
./extract-firmware.sh ./firmware
```

### Dynamic Analysis <a href="#dynamic-analysis" id="dynamic-analysis"></a>

```shellscript
gdb ./firmware
rizin ./firmware
```

#### Using FIRMADYNE <a href="#using-firmadyne" id="using-firmadyne"></a>

[**FIRMADYNE**](https://github.com/firmadyne/firmadyne) is a platform for emulation and dynamic analysis of Linux-based firmware.

```shellscript
# Analyze and emulate the system
./fat.py example.squashfs
```

The analysis will start.\
Copy the ip address in the output as below.

```shellscript
Network interfaces: [('brtrunk', '192.168.0.100')]
```

In local machine, port forward using the ip.

```shellscript
ssh -L 8081:192.168.0.100:80 remote-user@<remote-ip>
```

Now we can access to http://127.0.0.1:8081/
