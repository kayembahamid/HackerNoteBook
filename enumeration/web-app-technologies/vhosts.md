# Virtual Hosts (VHOSTS)



## Virtual Hosts (VHOSTS) Enumeration <a href="#virtual-hosts-vhosts-enumeration" id="virtual-hosts-vhosts-enumeration"></a>

We can find virtual hosts for websites by enumerating Host header value.

### Enumeration <a href="#enumeration" id="enumeration"></a>

```
# Ffuf
ffuf -u http://example.com/ -H "Host: FUZZ.example.com" -w wordlist.txt -fs 1234
# follow redirect (-r)
ffuf -u http://example.com/ -H "Host: FUZZ.example.com" -w wordlist.txt -fs 1234 -r
# Sometimes, we have to specify the ip address not domain.
ffuf -u http://10.0.0.1/ -H "Host: FUZZ.example.com" -w wordlist.txt -fs 1234

# Wfuzz
wfuzz -u http://example.com -H "Host: FUZZ.example.com" -w wordlist.txt --hl 138
```

#### Add Vhosts to Hosts File <a href="#add-vhosts-to-hosts-file" id="add-vhosts-to-hosts-file"></a>

If we found a vhost, add that ip\&domain to the hosts file depending on your attack machine.

* Linux: `/etc/hosts`
* Windows: `C:\Windows\System32\drivers\etc\hosts`

#### Related Domains <a href="#related-domains" id="related-domains"></a>

If we find the vhosts, we can try to search moreover with keywords.\
For instance, assume we found **“sub”** domain.

```shellscript
sub-api.example.com
sub-dev.example.com
sub-prod.example.com
sub-mail.example.com
sub-email.example.com

api-sub.example.com
dev-sub.example.com
prod-sub.example.com
mail-sub.example.com
email-sub.example.com
```

### OSINT <a href="#osint" id="osint"></a>

* [**nmmapper**](https://www.nmmapper.com/)

### SAN (Subject Alternative Name) in the Certificate <a href="#san-subject-alternative-name-in-the-certificate" id="san-subject-alternative-name-in-the-certificate"></a>

SAN is an extension to X.509 that allows various values to be associated with a security certificate using a subjectAltName field.\
We can also check it for finding subdomains.\
Replace **"example.com"** with your target domain.

```
openssl s_client -connect example.com:443 < /dev/null | openssl x509 -noout -text |
```

## Tools

### virtual-host-discovery

https://github.com/jobertabma/virtual-host-discovery

Example:

```bash
ruby scan.rb --ip=192.168.1.101 --host=domain.tld
```

### vhosts-sieve

https://github.com/dariusztytko/vhosts-sieve

Example:

```bash
python3 vhosts-sieve.py -d domains.txt -o vhosts.txt
```

### fierce

(fierce DNS scanner)

Example:

```bash
fierce -dns example.com
```

### VHostScan

https://github.com/codingo/VHostScan

Example:

```bash
VHostScan -t example.com
```

## Techniques

Reference: https://pentestbook.six2dez.com/enumeration/webservices/vhosts#techniques

Copy of common techniques:

```bash
# ffuf
badresponse=$(curl -s -H "host: totallynotexistsforsure.bugcrowd.com" https://bugcrowd.com | wc -c)
ffuf -u https://TARGET.com -H "Host: FUZZ.TARGET.com" -w werdlists/dns-hostnames/nmap-vhosts-all.txt -fs $badresponse

# Manual with subdomains list
for sub in $(cat subdomains.txt); do
    echo "$sub $(dig +short a $sub | tail -n1)" | anew -q subdomains_ips.txt
done
```
