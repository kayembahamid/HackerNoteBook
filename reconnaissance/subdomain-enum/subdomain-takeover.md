# Subdomain Takeover

## Active discovery

* Sublistr
* DNSRecon
* Amass
* Ffuf

```
ffuf -u <target> -w /path/to/wordlist.txt -H "Host: FUZZ.target.com" -fs <size-filter>
```

### Explanation

1. Domain name (sub.example.com) uses a CNAME record for another domain (sub.example.com CNAME anotherdomain.com).
2. At some point, anotherdomain.com expires and is available for anyone's registration.
3. Since the CNAME record is not removed from the DNS zone of example.com, anyone who records anotherdomain.com has full control over sub.example.com until the DNS record is present.

Subdomain Takeover is a malicious activity that the victim’s subdomain allows attackers to control and impersonate.

### Automation <a href="#automation" id="automation"></a>

First we need to enumerate subdomains. See [Subdomain Discovery](https://exploit-notes.hdks.org/exploit/reconnaissance/subdomain/subdomain-discovery/) for doing that. Then we can httpx for checking HTTP response status for each subdomain.

#### httpx <a href="#httpx" id="httpx"></a>

[https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)

```shellscript
# -title: Display page title
# -wc: Display response body word count
# -sc: Display response status-code
# -cl: Display response content-length
# -ct: Display response content-type
# -location: Display response redirect location
# -web-server: Display server name
# -asn: Display host ASN information
# -o: Output
cat domains.txt | httpx -title -wc -sc -cl -ct -location -web-server -asn -o alive-subdomains.txt

# Resume Scan (-resume)
# You can resume the scan using `resume.cfg`.
cat domains.txt | httpx -title -wc -sc -cl -ct -location -web-server -asn -o alive-subdomains.txt -resume resume.cfg
```

### Can I Take Over XYZ? <a href="#can-i-take-over-xyz" id="can-i-take-over-xyz"></a>

See [https://github.com/EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) to check if the provider allows us to register subdomains.

### CNAME Subdomain Takeover <a href="#cname-subdomain-takeover" id="cname-subdomain-takeover"></a>

#### 1. Identify Misconfigurations for Subdomains <a href="#id-1-identify-misconfigurations-for-subdomains" id="id-1-identify-misconfigurations-for-subdomains"></a>

Check DNS records for identifying what’s on the destination of the subdomain.

```shellscript
dig sub.example.com ANY
dig sub.example.com CNAME
```

If the HEADER status is **NXDOMAIN** error in the result, subdomain takeover might be possible.\
Also we can try to access them with web browser or command-line:

```shellscript
# -L: Follow redirect
# -v: Verbose mode
curl -Lv app.example.com
curl -v cloud.example.com
curl -v mail.example.com
```

#### 2. Spoof with the Subdomain <a href="#id-2-spoof-with-the-subdomain" id="id-2-spoof-with-the-subdomain"></a>

If a certain subdomain can be accessible but the error page of the specific provider (e.g. GitHub, Google Cloud, Wix, etc.) appeared, it means that the subdomain of the settings in the service provider was removed but the DNS record (e.g. A, CNAME) remains yet.

In short, attackers can spoof as a legitimate site by claiming this subdomain in the provider.

Here’s an abstract example:

1. Login the target provider.
2. Create a malicious website.
3. Add the target subdomain (e.g. app.example.com) as custom domain in the setting page.
4. If users visit app.example.com, they have now visited a malicious website created by an attacker.

### NS Subdomain Takeover <a href="#ns-subdomain-takeover" id="ns-subdomain-takeover"></a>

It’s more dangerous If NS record is vulnerable because if the nameserver is taken over, an attacker can take full control of victim’s domains.

To gather NS records for the target domain, use `dig` command.

```shellscript
dig example.com +short NS

# Result examples
ns-100.abcde.org
ns-120.abcde.co.uk
```

Next, check if the gathered domains can be purchased with domain name registrar like GoDaddy, NameCheap.

For example, search `[abcde.org](http://abcde.org)` in the domain search page of NameCheap. If this domain can be purchased, attackers can buy this domain then take control the name resolution of a victim by creating the custom nameserver which pointed to this domain.

### References <a href="#references" id="references"></a>

* [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
* [DrakenKun](https://medium.com/@DrakenKun/how-to-find-subdomain-takeover-using-httpx-dig-5c2351d380b4)

### Resources

{% embed url="https://0xpatrik.com/takeover-proofs/" %}

{% embed url="https://github.com/EdOverflow/can-i-take-over-xyz" %}
