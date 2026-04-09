# Using SSH

One of the [SSH hardening practice](https://linuxhandbook.com/ssh-hardening-tips/?ref=itsfoss.com) is to change the default SSH port. It reduces the number of bot attacks on the server.

The default SSH port number is 22. So when you use `ssh user@IP`, it tries to connect to the default port 22. But if the remote server uses some other port for SSH, you should provide the port number:

```
ssh -p port_number user@IP
```

Let's say you want to connect to a remote server with IP 64.227.184.93 that accepts SSH connections at port number 7770.

```
ssh -p 7770 abhishek@64.227.184.93
```

That was about connecting to a different port via SSH. What about changing the SSH port on your server?

### Change the default SSH port on Linux server <a href="#change-the-default-ssh-port-on-linux-server" id="change-the-default-ssh-port-on-linux-server"></a>

The process is simple:

* Decide which port number XXXX you want to use
* If you have an **active firewall on the server, allow the new port** XXXX
* Edit the `/etc/ssh/sshd_config` file and replace the line `#Port 22` with `Port XXXX`
* Restart the SSH service with `systemctl restart sshd`

Let's see it in details.

#### Step 1: Choose a port number <a href="#step-1-choose-a-port-number" id="step-1-choose-a-port-number"></a>

You can choose any port number between 0 and 65535 except the [common networking ports](https://linuxhandbook.com/common-ports/?ref=itsfoss.com) like 21, 80, 443 etc.

Can't pick. Let's say you use 7770 for the new SSH port.

Now, **log in to the server where you want to make these changes**.

#### Step 2: Allow the new port through the firewall <a href="#step-2-allow-the-new-port-through-the-firewall" id="step-2-allow-the-new-port-through-the-firewall"></a>

As a sysadmin you probably know if there is a firewall active on your system or not.

Different types of distributions have different firewalls. I cannot cover all of them so that onus lies on you.

I am using Ubuntu server and there you have the UFW. [Check the UFW firewall status](https://learnubuntu.com/check-firewall-status/?ref=itsfoss.com):

```
sudo ufw status
```

If it is active, [allow the new port through the firewall](https://learnubuntu.com/allow-port-firewall/?ref=itsfoss.com):

```
sudo ufw allow 7770
```

#### Step 3: Edit the ssh config file <a href="#step-3-edit-the-ssh-config-file" id="step-3-edit-the-ssh-config-file"></a>

[Use Vim or Nano](https://itsfoss.com/vim-vs-nano/) to edit the config file in the terminal. I'll use nano here:

```
nano /etc/ssh/sshd_config
```

In the file locate the line with `#Port 22`. It should be at the beginning of the file.



Change the line to `Port xxxx` format where xxxx is the port number you chose:\\

[Save the changes and exit the nano](https://itsfoss.com/nano-save-exit/) editor.

#### Step 4: Restart SSH service <a href="#step-4-restart-ssh-service" id="step-4-restart-ssh-service"></a>

Now that you have made changes to config file, [restart the service](https://itsfoss.com/start-stop-restart-services-linux/) SSH daemon.

Most distros these days use systemd and hence use this command to restart it:

```
systemctl restart sshd
```

And that's it. No need to restart the server itself.

Now when you have to connect to the server via SSH, specify the port number:

```
ssh -p xxxx user@ip
```



[Secure Shell (SSH)](https://en.wikipedia.org/wiki/SSH_\(Secure_Shell\)) is a network protocol that runs on port `22` by default and provides users such as system administrators a secure way to access a computer remotely. SSH can be configured with password authentication or passwordless using [public-key authentication](https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/) using an SSH public/private key pair.&#x20;

SSH can be used to remotely access systems on the same network, over the internet, facilitate connections to resources in other networks using port forwarding/proxying, and upload/download files to and from remote systems.

SSH uses a client-server model, connecting a user running an SSH client application such as `OpenSSH` to an SSH server. While attacking a box or during a real-world assessment, we often obtain cleartext credentials or an SSH private key that can be leveraged to connect directly to a system via SSH.&#x20;

An SSH connection is typically much more stable than a reverse shell connection and can often be used as a "jump host" to enumerate and attack other hosts in the network, transfer tools, set up persistence, etc. If we obtain a set of credentials, we can use SSH to login remotely to the server by using the username `@` the remote server IP, as follows:

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

It is also possible to read local private keys on a compromised system or add our public key to gain SSH access to a specific user, as we'll discuss in a later section.&#x20;

### Using Netcat <a href="#using-netcat" id="using-netcat"></a>

[Netcat](https://linux.die.net/man/1/nc), `ncat`, or `nc`, is an excellent network utility for interacting with TCP/UDP ports. It can be used for many things during a pentest. Its primary usage is for connecting to shells,  `netcat` can be used to connect to any listening port and interact with the service running on that port.&#x20;

For example, `SSH` is programmed to handle connections over port 22 to send all data and keys. We can connect to TCP port 22 with `netcat`:

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

As we can see, port 22 sent us its banner, stating that `SSH` is running on it. This technique is called `Banner Grabbing`, and can help identify what service is running on a particular port. `Netcat` comes pre-installed in most Linux distributions.&#x20;

We can also download a copy for Windows machines from this [link](https://nmap.org/download.html). There's another Windows alternative to `netcat` coded in PowerShell called [PowerCat](https://github.com/besimorhino/powercat). `Netcat` can also be used to transfer files between machines.

Another similar network utility is [socat](https://linux.die.net/man/1/socat), which has a few features that `netcat` does not support, like forwarding ports and connecting to serial devices. `Socat` can also be used to [upgrade a shell to a fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat).\
<br>

{% embed url="https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat" %}
