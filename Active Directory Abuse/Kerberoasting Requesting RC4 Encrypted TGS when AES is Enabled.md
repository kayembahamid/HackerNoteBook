
It is possible to kerberoast a user account with SPN even if the account supports Kerberos AES encryption by requesting an RC4 ecnrypted (instead of AES) TGS which easier to crack.

## Execution

First off, let's confirm we have at least one user with an SPN set:

**attacker\@victim**

```powershell
Get-NetUser -SPN sandy
```


![](assets/Kerberoasting%20Requesting%20RC4%20Encrypted%20TGS%20when%20AES%20is%20Enabled.png)

Since the user account does not support Kerberos AES ecnryption by default, when requesting a TGS ticket for kerberoasting with rubeus, we will get an RC4 encrypted ticket:

**attacker\@victim**

```
F:\Rubeus\Rubeus.exe kerberoast /user:sandy
```

![](assets/Kerberoasting%20Requesting%20RC4%20Encrypted%20TGS%20when%20AES%20is%20Enabled-1.png)


If the user is now set to support AES encryption:

![](assets/Kerberoasting%20Requesting%20RC4%20Encrypted%20TGS%20when%20AES%20is%20Enabled-2.png)
By default, returned tickets will be encrypted with the highest possible encryption algorithm, which is AES:

attacker\@victim

```
F:\Rubeus\Rubeus.exe kerberoast /user:sandy
```


![](assets/Kerberoasting%20Requesting%20RC4%20Encrypted%20TGS%20when%20AES%20is%20Enabled-3.png)

## Requesting RC4 Encrypted Ticket

As mentioned in the beginning, it's still possible to request an RC4 ecnrypted ticket (if RC4 is not disabled in the environment, which does not seem to be common yet):

attacker\@victim

```
F:\Rubeus\Rubeus.exe kerberoast /tgtdeleg
```

{% endcode %}

Even though AES encryption is supported by both parties, a TGS ticket encrypted with RC4 (encryption type 0x17/23) was returned. Note that SOCs may be monitoring for tickets encrypted with RC4:

![](https://386337598-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LeCY_41BsTXRMR1qJh9%2F-LeCevY4uZ_2GNzRqOYZ%2FScreenshot%20from%202019-05-06%2016-03-06.png?alt=media\&token=68ad84b3-ed76-4e27-b742-ac631b02173f)

## References

{% embed url="<https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/>" %}
