

This lab explores a couple of common cmdlets of PowerView that allows for Active Directory/Domain enumeration.

## Get-NetDomain

Get current user's domain:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration.png)
## Get-NetForest

Get information about the forest the current user's domain is in:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-1.png)
## Get-NetForestDomain

Get all domains of the forest the current user is in:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-2.png)
## Get-NetDomainController

Get info about the DC of the domain the current user belongs to:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-3.png)
## Get-NetGroupMember

Get a list of domain members that belong to a given group:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-4.png)
## Get-NetLoggedon

Get users that are logged on to a given computer:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-5.png)
## Get-NetDomainTrust

Enumerate domain trust relationships of the current user's domain:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-6.png)
## Get-NetForestTrust

Enumerate forest trusts from the current domain's perspective:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-7.png)
## Get-NetProcess

Get running processes for a given remote machine:

```csharp
Get-NetProcess -ComputerName dc01 -RemoteUserName offense\administrator -RemotePassword 123456 | ft
```

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-8.png)
## Invoke-MapDomainTrust

Enumerate and map all domain trusts:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-9.png)
## Invoke-ShareFinder

Enumerate shares on a given PC - could be easily combines with other scripts to enumerate all machines in the domain:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-10.png)
## Invoke-UserHunter

Find machines on a domain or users on a given machine that are logged on:

![](../../../../assets/PowerView%20Active%20Directory%20Enumeration-11.png)
## References

**GitHub - PowerShellMafia/PowerSploit: PowerSploit ** - A PowerShell Post-Exploitation Framework
GitHub{% embed url="<https://github.com/PowerShellMafia/PowerSploit>" %}
