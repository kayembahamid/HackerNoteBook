# Basic recon

Basic reconnaisance flows.

### Automation <a href="#automation" id="automation"></a>

* [AutoRecon](https://github.com/Tib3rius/AutoRecon)
* [FinalRecon](https://github.com/thewhiteh4t/FinalRecon)
* [recon-ng](https://github.com/lanmaster53/recon-ng)
* [reconftw](https://github.com/six2dez/reconftw)
* [theHarvester](https://github.com/laramies/theHarvester)

### Acquisitions <a href="#acquisitions" id="acquisitions"></a>

We need to find the other companies which are owned by the target company.

* [CrunchBase](https://www.crunchbase.com/)

### ASN <a href="#asn" id="asn"></a>

An autonomous system number (ASN) is a collection of connected IP routing prefixes under the control of network operators. It is assigned to an autonomous system (AS) by the **Internet Assigned Numbers Authority (IANA)**.\
**Border Gateway Protocol (BGP)** is used to notify the routing policy to the other AS or routers.\
We can also find IP ranges belonging to the ASN.

* [BGP Toolkit](https://bgp.he.net/)
* [ASN Lookup](https://asnlookup.com/)

### WHOIS <a href="#whois" id="whois"></a>

whois is used to find information about the registered users of the domain.

```
whois example.com
```

### Archived Web Pages <a href="#archived-web-pages" id="archived-web-pages"></a>

[Wayback Machine](http://web.archive.org/) is an online tool that archives a lot of websites.

### Subnet Scan <a href="#subnet-scan" id="subnet-scan"></a>

You need only the **ping scan (skip port scan)** by adding the option **"-sP"**.

```shellscript
# /24 - 255.255.255.0
nmap -sP <target-ip>/24 -T2
# /16 - 255.255.0.0
nmap -sP <target-ip>/16 -T2
# /8 - 255.0.0.0
nmap -sP <target-ip>/8 -T2
```

### Port Scan <a href="#port-scan" id="port-scan"></a>

See [Port Scan](https://exploit-notes.hdks.org/exploit/reconnaissance/port-scan/) for details.

### Subdomains <a href="#subdomains" id="subdomains"></a>

See also [Subdomain Discovery](https://exploit-notes.hdks.org/exploit/reconnaissance/subdomain/subdomain-discovery/), [DNS Pentesting](https://exploit-notes.hdks.org/exploit/dns/).

#### Google Search <a href="#google-search" id="google-search"></a>

For example, input `site:facebook.com` in the search form. We should see a list of subdomains for the facebook.com.

#### VirusTotal <a href="#virustotal" id="virustotal"></a>

For example, input "facebook.com" in the search form of the URL section. We shoud see a list of subdomains for the facebook.com in the `RELATIONS` section.

*   **Subdomain Takeover**

    It allows an adversary to claim and take control of the victim's subdomain.

    Resource: [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)

### Social Accounts <a href="#social-accounts" id="social-accounts"></a>

We can get more information if the organization uses social platforms as below.

* Discord
* Facebook
* GitHub
* Mastodon
* Reddit
* Twitter

### Trace Route Packets <a href="#trace-route-packets" id="trace-route-packets"></a>

To track the route packets from our IP to target host, run the following command.

```
traceroute example.com
```

### Find Vulnerabilites <a href="#find-vulnerabilites" id="find-vulnerabilites"></a>

#### Automation <a href="#automation_1" id="automation_1"></a>

*   **Nuclei**

    [Nuclei](https://github.com/projectdiscovery/nuclei) is a vulnerability scanner based on simple YAML based DSL.

    ```
    nuclei -h
    ```

#### Exploit DB <a href="#exploit-db" id="exploit-db"></a>

You can search vulnerabilites written in Exploit-DB by using "searhsploit".

```
searchsploit <keyword>
```

If you found vulnerabilities of target, copy them to current directory.\
For example,

```
searchsploit -m windows/remote/42031.py
# or
searchsploit -m 42031
```

[Exploit-DB](https://www.exploit-db.com/) is a database of exploits.\
Find the exploit and download it. For example:

```
wget https://www.exploit-db.com/raw/42966 -O exploit.py
```

Format the exploit code for UNIX.

```
dos2unix exploit.py

# Manual converting
sed -i 's/\r//' example.py
```

### References <a href="#references" id="references"></a>

* [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
