# BugBounty Methodology

## Recon / Web Hacking

Tags: #recon #webhacking

Links

* [**bugbountyhunter**](https://www.bugbountyhunter.com/)
* [**HTML sandbox**](https://www.jsfiddle.net/)
* [**JavaScript sandbox**](https://www.jsbin.com/)

### How websites work with HTML, CSS and JavaScript

(Use the sandboxes above to quickly test HTML/JS payloads and behavior.)

### Don't overcomplicate things

* Logging in
* Commenting on a post

### Questioning (when investigating)

* What did they consider when setting this up?
* Can I maybe find a vulnerability here?
* Can you comment with basic HTML such as `<h2>` — where is it reflected on the page?
* Can I input XSS in my name?
* Does it make any requests to an /api/endpoint which may contain more interesting endpoints?
* Can I edit this post? Maybe there's IDOR?!

### Developer experience

* [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings)
* Try to understand what a payload is trying to achieve: why/how it was created, what it does, and why it was needed.
* Combine payload understanding with experimenting with basic HTML and tracing the code path (POST vs GET, JSON bodies, etc).
* Brute force common parameter names — you can get lucky.
* Be curious and try things — you can't be wrong.

### Real-life example / Vulnerability Disclosure program

Google for companies ready to work with researchers:

* “responsible disclosure program”
* “vulnerability disclosure program”
* “vulnerability program rewards”
* inurl: vulnerability disclosure
* inurl: responsible disclosure

### My basic toolkit

Use the stepper below for a quick overview of core tooling and commands.

{% stepper %}
{% step %}
### Burp Suite

* For intercepting, modifying, and repeating requests on the fly.
* Community edition works; Professional adds plugins and Collaborator support.
* Links:
  * Burp Collaborator client: https://portswigger.net/burp/documentation/collaborator/deploying
  * BApp Store: https://portswigger.net/bappstore
{% endstep %}

{% step %}
### OWASP Amass — subdomain discovery

* Uses many sources (passive + active) for discovery.
* Repo: https://github.com/OWASP/Amass
* Example:
  * `amass enum -brute -active -d domain.com -o amass-output.txt`
{% endstep %}

{% step %}
### httprobe — find working HTTP/HTTPS servers

* Repo: https://github.com/tomnomnom/httprobe
* Example:
  * `cat amass-output.txt | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 | tee online-domains.txt`
{% endstep %}

{% step %}
### anew — dedupe domain lists

* Repo: https://github.com/tomnomnom/anew
* Note: plays nicely to print new domains to stdout.
* Example: `cat new-output.txt | anew old-output.txt | httprobe`
{% endstep %}

{% step %}
### dnsgen — generate permutations for subdomain discovery

* Repo: https://github.com/ProjectAnte/dnsgen
* Example: `cat amass-output.txt | dnsgen - | httprobe`
{% endstep %}

{% step %}
### Aquatone — visual inspection

* Repo: https://github.com/michenriksen/aquatone
* Accepts endpoints and files (not just domains).
* Example: `cat domains-endpoints.txt | aquatone`
{% endstep %}

{% step %}
### FFUF — fast and customizable fuzzing

* Repo: https://github.com/ffuf/ffuf
* Example: `ffuf -ac -v -u https://domain/FUZZ -w wordlist.txt`
{% endstep %}

{% step %}
### Wordlists

* SecLists: https://github.com/danielmiessler/SecLists/
* Grab a list and start scanning — pick domain-appropriate wordlists for best results.
{% endstep %}

{% step %}
### CommonSpeak — generate keyword-based wordlists

* Repo: https://github.com/pentester-io/commonspeak
* Usage: https://pentester.io/commonspeak-bigquery-wordlists/
{% endstep %}

{% step %}
### Custom tools and GitHub collections

* Example: tools by tomnomnom: https://github.com/tomnomnom
* Search GitHub for useful scripts and tooling.
{% endstep %}

{% step %}
### WaybackMachine scanner / archival reconnaissance

* Scrapes /robots.txt and homepage of subdomains, then scans endpoints.
* Public tool: https://gist.github.com/mhmdiaa
* Old indexed files can still be revealing.
{% endstep %}

{% step %}
### ParamScanner & JS URL discovery

* Custom tools that scrape endpoints and search for input names/IDs and JS variables like var{name} = "".
* Links:
  * Javascript file scraping gist: https://gist.github.com/mhmdiaa
  * LinkFinder: https://github.com/GerbenJavado/LinkFinder
  * parameth (parameter brute forcing): https://github.com/maK-/parameth
{% endstep %}
{% endstepper %}

{% hint style="danger" %}
Note: my tool trend is to find new content, parameters, and functionality to poke at.
{% endhint %}

### Common issues I start with & why

* Stick to what you know to create impact.
* Developers repeat mistakes; find and exploit common patterns.
* Look through design, frameworks in use, filters in place, and aim to bypass them.

***

## 1. Cross-Site Scripting (XSS)

Tags: #xss

* One of the most common vulnerabilities on bug bounty programs.
* Inject HTML into a parameter/field that gets reflected and rendered as HTML.
  * Example: Search form -> Enter `<img src=x onerror=alert(0)>` and an alert appears.
* Test every parameter; look for reflected, stored, and blind XSS.
* Bypassing WAFs is iterative and often a trial-and-error process.
  * Awesome-WAF: https://github.com/0xInfection/Awesome-WAF
* Filters can reveal developer assumptions and possible bypasses.
* Create a lead when you find potential XSS.

Process for testing for XSS & filtering (stepper)

{% stepper %}
{% step %}
### Testing encodings and behavior

* Find what payloads are allowed and how the website reflects/handles them:
  * Try `<h2>, <img>, <table>` and see if they're reflected as HTML.
  * Check if characters are encoded (e.g., `&lt;` vs `%3c` vs double-encoded `%253C`).
* Try many encodings (see ghettoBypass): https://d3adend.org/xss/ghettoBypass
* Example: `<script>` reflected as `&lt;script&gt;` but `%26itscript%26gt` becomes `<script>` — indicates a possible bypass.
{% endstep %}

{% step %}
### Reverse-engineering developer filters

* Get into the developer's head: what filters are in place and why? Where else in the app are they applied?
* Examples to consider:
  * Are they blacklisting `<script>`, `<iframe>`, `onerror=` but miss `<svg>` or `<scriptsrc=...`?
  * Are they only matching complete HTML tags? Are encodings like `<00iframe>` or `on%0derror` handled?
* Keep testing different combinations and encodings.
* More payloads: https://zseano.com/
{% endstep %}

{% step %}
### Testing XSS flows

* How do non-malicious tags like `<h2>` behave?
* What about incomplete tags: `<iframe src=//hamcodes.com/c=`?
* Test encodings: `%0d`, `%0a`, `%09`, `%00`, etc.
* Try case and syntax variations: `</script/x>`, `<ScRipt>`, etc.
* This process helps determine the filtering and whether a parameter is likely vulnerable.
{% endstep %}
{% endstepper %}

Helpful resource: Filter bypass cheat sheet — https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet

***

## 2. Cross-Site Request Forgery (CSRF)

Tags: #csrf

* Forcing a user to perform an action on the target site via a crafted request (e.g., an HTML form POST).
* Example impact: force-change account email to attacker-controlled address => potential account takeover.
* Developers can protect CSRF easily, but custom implementations can introduce flaws.

Testing tips and questions:

* Look at sensitive areas (account update, password change, checkout).
* What happens with a blank or malformed CSRF token? Does an error reveal framework info?
* Are protections consistent across features (mobile vs web, different endpoints)?
* Some servers only check the Referer header; creative methods can bypass Referer checks (e.g., meta referrer, data URIs, domain variations).
* If you find custom CSRF defenses, look for bypasses — where there is a filter, there may be a bypass.

***

## 3. Open URL Redirects

* Favorite bug often with high success because many developers implement naive redirects.
* Example: https://www.google.com/redirect?goto=https://www.bing.com/ — if goto is unfiltered, it redirects anywhere.
* Useful payload patterns to probe filter behavior (try variants and encodings exactly as listed — keep the payloads intact while testing):
  * `\/yoururl.com`, `\/\/yoururl.com`, `\\yoururl.com`, `//yoururl.com`, `//theirsite@yoursite.com`, `/\/yoursite.com`, `https://yoursite.com%3F.theirsite.com/`, `https//yoursite.com%2523.theirsite.com/`, `https://theirsite.computer/`, `https://theirsite.com.mysite.com`, `/%0D/yoursite.com`, `/%2F/yoururl.com`, `/%5Cyoururl.com`, `//google%E3%80%82com`, etc.
* Common parameter names to dork for: `return`, `return_url`, `rUrl`, `cancelUrl`, `url`, `redirect`, `goto`, `returnTo`, `returnUrl`, `history`, `redirectTo`, `redirectUrl`, `redirUrl`, etc.
* Open redirects can be chained into OAuth flows to leak tokens — watch for login flows with redirect parameters.
* Encoding and double-encoding tricks help with multi-step redirects and parameter preservation.
* Open redirects may also enable SSRF or XSS depending on how the redirect is executed (Location header vs window.location vs javascript:).

Example bypass tricks (encoded obfuscation):

* `java%0d%0ascript%0d%0a:alert(0)`
* `j%0d%0aava%0d%0aas%0d%0acrip%0d%0at%0d%0a:confirm\`0\`\`
* `java%09scrip%07t:prompt\`0\`\`
* Repeating or inserting junk characters in "javascript" (various mutations) to bypass simple filters.

OAuth reference: https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2.

***

## Server-Side Request Forgery (SSRF)

Tags: #SSRF

* In-scope domain issues a request to a URL you control or specify.
* Look for features accepting a URL parameter: API consoles, webhooks, developer tools.
* Test how redirects are handled by the server — host redirects locally (e.g., XAMPP + ngrok) to observe behavior and timing.
* Try timing attacks (add sleep in the redirect target) to detect server-side fetches.
* Check whether the application follows redirects and if internal resources can be read.
* Look for third-party software (Jira, Confluence, etc.) and known CVEs — these may expose server features.
* Stay up-to-date with CVEs and check if filters are only superficial.

***

## File uploads (stored XSS & RCE)

Tags: #xss

* Developers often filter allowed file types incorrectly.
* Files stored on the domain can allow stored XSS or remote code execution.
* Test uploading atypical but plausible files: `.txt`, `.svg`, `.xml` — sometimes forgotten by filters.
* Test file name tricks and encoding to smuggle content or change perceived extension:
  * `hamcodes.php/.jpg`
  * `hamcodes.html%0d%0a.jpg` (newline characters can result in saved `.html`)
* Filenames can be reflected on pages; characters like `<svg onload=...>` embedded in filenames may render.
* Test content-type vs extension handling: server may trust extension or content-type inconsistently.

Example payload (multipart form filename containing SVG):

```shellscript
------WebKitFormBoundarySrtFN30pCNmqmNz2
Content-Disposition: form-data; name="file"; filename="58832_300x300.jpg<svg onload=confirm()>"
Content-Type: image/jpeg
ÿØÿà 
```

Other malformed examples to test how the server treats content-type and filename:

```shellscript
------WebKitFormBoundaryAxbOlwnrQnLjU1j9
Content-Disposition: form-data; name="imageupload"; filename="hamcodes.jpg" 
Content-Type: text/html
```

```shellscript
------WebKitFormBoundaryAxbOlwnrQnLjU1j9
Content-Disposition: form-data; name="imageupload"; filename="hamcodes." 
Content-Type: text/html
```

```shellscript
------WebKitFormBoundaryAxbOlwnrQnLjU1j9
Content-Disposition: form-data; name="imageupload"; filename=".html" 
Content-Type: image/png
<html>HTML code!</html>
```

Another example showing an image filter bypass:

```shellscript
------WebKitFormBoundaryoMZOWnpiPkiDc0yV
Content-Disposition: form-data; name="oauth_application[logo_image_file]"; filename="testing1.html"
Content-Type: text/html
‰PNG 
<script>alert(0)</script>
```

Spend time testing file upload filters — it’s often fruitful.

***

## Insecure Direct Object Reference (IDOR)

Tags: #IDOR

* Example: `http://api.hamcodes.com/user/1` returns user 1. Changing ID to 2 should be blocked; if not, it's IDOR.
* IDOR is about changing identifiers (integers, GUIDs, etc.) and observing access control failures.
* GUID brute force is usually impractical; instead, look for leaks where the ID appears elsewhere (images, URLs).
* Example path leak: `/images/users/2b7498e3-9634-4667-b9ce-a8e81428641e/photo.png`
* Questions:
  * Is the value leaked anywhere? Indexed by Google?
  * Search for keywords like "appointment", "appointmentID".
* Check mobile apps — APIs used in mobile apps are often fruitful for IDOR.
* Try injecting `id` fields into JSON payloads or adding parameters; check PUT requests and other verbs.

***

## CORS (Cross-Origin Resource Sharing)

Tags: #cors

* Check for `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`.
* If `Access-Control-Allow-Origin` echoes or allows attacker-controlled origins, an external site could read sensitive responses.
* `Access-Control-Allow-Credentials: true` is required if cookies or credentials are involved.
* Where filters exist, seek bypasses (e.g., slightly modified origin values).
* Grep for `Access-Control-Allow-Origin` in responses after setting various `Origin` headers.

***

## SQL Injection

Tags: #SQL

* More common in legacy code and old features.
* Test places that query the database with user input.
* Error messages may be suppressed; use blind SQL techniques such as time-based payloads:
  * `or sleep(15) and 1=1#`
  * `or sleep(15)#`
  * `union select sleep(15),null#`
* Use 15–30s delays to detect blind SQL execution.
* Apply similar systematic testing across the application.

***

## Business / Application Logic bugs

* Understand how the application is intended to work and abuse logic to cause unexpected outcomes (price manipulation, privilege escalation, bypassing payment checks).
* Look for interactions between new features and legacy flows.
* Example: sign up with special email addresses (company domains) that may grant different privileges.
* Logic bugs require understanding intended flows and identifying places to deviate.

***

## Choosing a program (Seven-step methodology)

* Spend months on a program; big companies take longer to find issues.
* Choose broad scope and well-known names (more surface area).
* Focus on platforms you know and expand attack surface by scanning subdomains, files, and directories.
* Spend time getting into developers' heads; build a comprehensive mind-map of the company and how components interact.
* Don't rush — trust the process.

***

## Checklist for a well-run bug bounty program

* Direct communication or reliance on platform (if managed service, proceed cautiously).
* Active program — when was scope last updated?
* How does the team handle low-hanging bugs that can be chained?
* Do they reward higher-impact findings appropriately?
* Response time across 3–5 reports should ideally not exceed a month.
* Don't be afraid to walk away from bad experiences.

***

## Writing notes as you hack

* Save notes to avoid burnout and to keep a clear record of findings.
* Track:
  * Interesting endpoints
  * Behaviors and parameters
  * Features that can/can't be exploited
  * What you've tried and what you believe is vulnerable
* Notes help create custom wordlists (domain-specific endpoints and parameters).
* Build domain-specific endpoints and params files and reuse across targets.

***

## Let's apply the methodology & hack!

{% stepper %}
{% step %}
### Step one: Getting a feel for things

* Has anyone else written a disclosure or writeup? Check Google, HackerOne, OpenBugBounty.
  * https://www.google.com/?q=domain.com+vulnerability
  * https://www.hackerone.com/hacktivity
  * https://www.openbugbounty.org/
* Analyze the main website flow: login, register, upload, etc.
* Questions to ask on first look:
  * Can I login with social media?
  * Do different geolocations affect login options?
  * What characters are allowed in inputs?
  * Are inputs reflected anywhere (bio, posts)?
  * Does the mobile signup use a different codebase?
* Key features to inspect:
  * Registration: required fields, where reflected, photo upload handling, display name and bio filtering.
  * Social login: OAuth implementation and what info is trusted.
  * Allowed characters: try `<script`, unicode, `%00`, `%0d`.
  * Check login redirects and parameters (`returnUrl`, `goto`, etc).
  * Inspect JS files for endpoints and hidden functionality.
  * Use Google dorks to see what Google indexes about registration/login pages.
{% endstep %}

{% step %}
### Step two: Expanding the attack surface

* Run subdomain scanning tools and look for domains with functions (login, upload, api, developer, etc).
* Google dork common keywords: `login, register, upload, contact, feedback, join, signup, profile, user, comment, api, developer, affiliate, careers, upload, mobile, upgrade, passwordreset`.
* Dork for file extensions: `php, aspx, jsp, txt, xml, bak`.
* Search GitHub, Shodan, BinaryEdge for leaked secrets (api\_key, api\_secret, passwords).
* Use robots.txt (via scanning) to find endpoints the site owner didn't want indexed.
* Use Wayback Machine to find historical endpoints and files.
* Fuzz directories and files with FFUF and CommonSpeak.
* Check GET vs POST differences — vulnerabilities may exist only for one method.
{% endstep %}

{% step %}
### Step three: Automate, rinse & repeat

* Use recon automation (e.g., lazyrecon by NahamSec): https://github.com/nahamsec/lazyrecon
* Stay updated on new programs and disclosures (Twitter feeds, mailing lists).
* Follow writeups and communities to learn new tricks and bypasses.
* Build and refine custom wordlists and tooling for recurring targets.
{% endstep %}
{% endstepper %}

***

## Useful resources & links

* Common payloads and bypasses:
  * https://github.com/swisskyrepo/PayloadsAllTheThings
  * https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet
  * https://d3adend.org/xss/ghettoBypass
  * Open Redirect payloads: https://github.com/cujanovic/Open-Redirect-Payloads/blob/master/Open-Redirect-payloads.txt
* Recon & tooling:
  * CertSpotter API: https://certspotter.com/api/v0/certs?domain=domain.com
  * URL encoding reference: http://www.degraeve.com/reference/urlencoding.php
  * APK scan: https://apkscan.nviso.be/
  * PublicWWW (search HTML/JS/CSS): https://publicwww.com/
  * Pentester resources: https://pentester.land
  * Bug bounty writeups: https://medium.com/bugbountywriteup
* Sandboxes:
  * https://www.jsfiddle.net
  * https://www.jsbin.com/
* Recon helpers:
  * https://www.yougetsignal.com/tools/web-sites-on-web-server/
  * https://apkscan.nviso.be/
  * https://publicwww.com/



