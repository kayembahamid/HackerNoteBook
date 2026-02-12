# Privacy

## Anonymize Traffic with Tor <a href="#anonymize-traffic-with-tor" id="anonymize-traffic-with-tor"></a>

We can anonymize our traffic using Tor proxy and proxychains. Please note that this method does not provide complete anonymity.

### Privacy Friendly OS <a href="#privacy-friendly-os" id="privacy-friendly-os"></a>

* Tails
* Qubes
* Whonix

### Anonymization <a href="#anonymization" id="anonymization"></a>

#### 1. Configure Proxychains <a href="#id-1-configure-proxychains" id="id-1-configure-proxychains"></a>

First off, find the location of the proxychains configuration file.

```shellscript
find / -type f -name "*proxychains*" 2>/dev/null
```

Assume we found **`/etc/proxychains.conf`** then modify this file.

```shellscript
vim /etc/proxychains
```

We need to remove **`#`** in front of **`dynamic_chains`**, then comment out the **`strict_chain`** line and the **`random_chain`** line.\
In addition, check the **`proxy_dns`** is uncommented for avoiding our DNS to be leaked.

```shellscript
...

dynamic_chain

...

# strict_chain

...

# random_chain

...

proxy_dns
```

Add **`socks4 127.0.0.1 9050`** and **`socks5 127.0.0.1 9050`** in the **`ProxyList`** section.

```shellscript
[ProxyList]
socks4  127.0.0.1 9050
socks5  127.0.0.1 9050
```

#### 2. Start Tor Service <a href="#id-2-start-tor-service" id="id-2-start-tor-service"></a>

Before using proxychains, we need to start Tor service.

```shellscript
systemctl start tor

# Check the status
systemctl status tor
```

#### 3. Use Proxychains <a href="#id-3-use-proxychains" id="id-3-use-proxychains"></a>

Now we can execute arbitrary command with proxychains. Our traffic should be anonymous thanks to Tor.

```shellscript
# Open Firefox browser.
proxychains firefox dnsleaktest.com

proxychains nmap x.x.x.x
```

* **Check Public IP**

To check our public ip address from command line, run the following command.

```shellscript
proxychains curl ifcfg.me
```

* **Proxhchains Bash**

If we don't want to append **`proxychains`** command every time, **`proxychains bash`** command eliminates the need to do that.

```shellscript
proxychains bash

# Confirm our public ip
curl ifcfg.me
```

#### 4. Use Burp Suite <a href="#id-4-use-burp-suite" id="id-4-use-burp-suite"></a>

To use **Burp Suite** over **Tor proxy**, setup the **SOCKS** proxy in Burp Suite as below.

1. Open **Burp Suite**. We need to normally start Burp Suite **without `proxychains`** command.
2. Go to **Proxy** tab and click **Proxy** settings. **Settings** window opens.
3. In **Settings** window, go to **User** tab at the left pane, and click **Network → Connections**.
4.  In **SOCKS proxy** section, click the switch **"Override options for this project only"**, and fill the following forms:

    ```shellscript
    SOCKS proxy host: 127.0.0.1
    SOCKS proxy port: 9050
    ```

    5\. After that, check **"Use SOCKS proxy"**. 6. Close the **Settings** window.

After setting up, we can use **Burp Suite built-in browser** over **Tor proxy**.

#### 5. Stop Tor Service <a href="#id-5-stop-tor-service" id="id-5-stop-tor-service"></a>

After using proxychains and Tor, stop the Tor service.

```shellscript
systemctl stop tor
```

### Check Your IP <a href="#check-your-ip" id="check-your-ip"></a>

After anonyzation, check your ip.

[https://www.dnsleaktest.com/](https://www.dnsleaktest.com/)

### Change MAC Address <a href="#change-mac-address" id="change-mac-address"></a>

```shellscript
macchanger -r ens33
```

### References <a href="#references" id="references"></a>

* [Geekflare](https://geekflare.com/anonymize-linux-traffic/)
* [0x00sec 1](https://0x00sec.org/t/how-to-become-a-ghost-hacker-merozey-tips/591)
* [0x00sec 2](https://0x00sec.org/t/anonymity-basics/722)
* [Edureka](https://www.edureka.co/blog/proxychains-anonsurf-macchanger-ethical-hacking/)
