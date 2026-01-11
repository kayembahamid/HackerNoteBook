
This lab shows how it is possible to use Powershell to enumerate Active Directory with Powershell's `Active Directory` module on a domain joined machine that does not have Remote Server Administration Toolkit (RSAT) installed on it. Installing RSAT requires admin privileges and is actually what makes the AD Powershell module available and this lab shows how to bypass this obstacle.

## Execution

The secret to being able to run AD enumeration commands from the AD Powershell module on a system without RSAT installed, is the DLL located in `C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management` on a system that **has the RSAT** installed:

![](assets/Active%20Directory%20Enumeration%20with%20AD%20Module%20without%20RSAT%20or%20Admin%20Privileges.png)
This means that we can just grab the DLL from the system with RSAT and drop it on the system we want to enumerate from (that does not have RSAT installed) and simply import that DLL as a module:

```csharp
Import-Module .\Microsoft.ActiveDirectory.Management.dll
```

Note how before we import the module, `Get-Command get-adcom*` returns nothing, but that changes once we import the module:

![](assets/Active%20Directory%20Enumeration%20with%20AD%20Module%20without%20RSAT%20or%20Admin%20Privileges-1.png)
As mentioned earlier, this does not require the user have admin privileges:

![](assets/Active%20Directory%20Enumeration%20with%20AD%20Module%20without%20RSAT%20or%20Admin%20Privileges-2.png)
## Download Management.DLL


https://386337598-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LXnewZ4PrS2xFJwBJbD%2F-LXnmT6gbXUvKgr_h3AE%2FMicrosoft.ActiveDirectory.Management.dll?alt=media&token=dca25388-9b28-4744-9333-462445d65ab6

## Reference

{% embed url="<https://scriptdotsh.com/index.php/2019/01/01/active-directory-penetration-dojo-ad-environment-enumeration-1/>" %}
