# Cross site request forgery (CSRF) Token

## What is CSRF?

* This allows an attacker to perform actions that the victim does not intend to perform.
* This allows an attacker to circumvent the same-origin policy<br>

## Impact of a CSRF attack

* The attacker causes the victim user to carry out an action unintentionally:
  * Changing the email address on their account
  * Changing their password
  * Making a fund transfer

## How CSRF works

* Three conditions must be in place:
  * A relevant action to induce:
    * A privileged action such as modifying permissions for users
    * User-specific data such as changing the user's own password
  * Cookie-based session handling:
    * Performing the action involves issuing one or more HTTP requests
    * The application relies solely on session cookies to identify the user who made the request
    * No other mechanism is in place for tracking sessions or validating user requests
  * Predictable request parameters:
    * Easy to guess or determine parameters
    * Easy to guess or determine values
* Example of a request that meets all the conditions:

```http
POST /email/change HTTP/1.1                         1. =>(A relevant action to induce) 
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded     2. =>(predictable request parameters)
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE    3. =>(Cookie-based session handling)

email=wiener@normal-user.com
```

* Example attacker HTML that auto-submits the change request when the victim visits the page:

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

## Construct a CSRF attack

* Burp Suite Professional: use Engagement tools → Generate CSRF PoC
  * Select a request in Burp
  * Right-click → Engagement tools → Generate CSRF PoC
  * Burp generates HTML that triggers the selected request (cookies are not included; the victim's browser will add them)
  * Tweak options if needed, copy the HTML into a web page, view in a browser logged in to the vulnerable site to test

## Labs and exploit patterns

### Lab: CSRF vulnerability with no defenses

{% stepper %}
{% step %}
### Introduction

Web\_Pentest: Pen-tester infiltrates a website with a CSRF vulnerability where the "Update Email" functionality lacks defenses. CSRF allows an attacker to trick a user into performing actions they didn't intend, like changing their email address by embedding a malicious request within a page the victim visits.
{% endstep %}

{% step %}
### Vulnerability - Problem

* Source:
  * No CSRF Protection: The server does not require any unique token or verification that would stop requests from external sites.
* Sink:
  * Automatic Form Submission: The auto-submit script sends the request instantly without user interaction.
* Challenge:
  * Trick the victim into visiting the malicious link.
{% endstep %}

{% step %}
### Payload & End-goal

Craft an HTML form that, when loaded by the victim, automatically sends a POST request to change their email.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Initial Test:
  * Run Burp Suite, log into the account using provided credentials.
  * Update email: submit the form with a new email.
* Inspect:
  * Check proxy history for the captured request changing the email.
  * Right-click the request → Engagement tools → Generate CSRF PoC.
{% endstep %}

{% step %}
### Attack (Manual / Community Edition)

* Craft a simple HTML template:
  * Replace YOUR\_LAB\_ID in the URL for the lab environment.
  * Use method="POST", action pointing to the vulnerable URL.
  * Include a hidden input for the new email.
  * Auto-submit via script: document.forms\[0].submit();
* Inject the payload:
  * Go to the exploit server in the lab, paste the HTML into the body, click Store.
* Test:
  * Click View exploit to test.
  * Check account information to confirm email change.
  * Modify the email in the form to ensure it doesn't match your own email before final delivery.
{% endstep %}

{% step %}
### Deliver & Verify

* Go to the exploit server and click Deliver to victim.
* The simulated victim visits the page and the form submits, changing their email address.
{% endstep %}
{% endstepper %}

<details>

<summary>Why the exploit works</summary>

* The application accepts cross-origin requests that contain the victim's session cookie and there is no token or validation to prevent such requests.
* Automatic submission causes the victim's browser to issue the authenticated request without user intent.

</details>

Real-world impact: account takeover, loss of privacy, financial or reputational damage.

HTML template:

```html
<html>
  <body>
      <form action="https://vulnerable-website.com/email/change" method="POST">
          <input type="hidden" name="email" value="pwned@evil-user.net" />
      </form>
      <script>
          document.forms[0].submit();
      </script>
  </body>
</html>
```

***

### Lab: CSRF where token validation depends on request method

{% stepper %}
{% step %}
### Introduction

Web\_Pentest: The site attempts to prevent CSRF by applying tokens, but only for certain request types.
{% endstep %}

{% step %}
### Vulnerability - Problem

* Source:
  * CSRF token validation is applied only to POST requests.
  * Changing the request type from POST to GET can bypass CSRF defenses.
{% endstep %}

{% step %}
### Payload & End-goal

Create an exploit that changes the victim's email by hosting a malicious HTML page that issues a GET request (or otherwise avoids CSRF-protected methods).
{% endstep %}

{% step %}
### Reconnaissance Plan

* Initial Test:
  * Login using Burp's browser, go to Update Email and submit a new email.
* Inspect:
  * Capture the request in Proxy and send to Repeater.
  * Modify the CSRF parameter → request rejected (CSRF required for POST).
  * Change the method to GET, remove CSRF parameter → request still works → defense only applied to POST.
{% endstep %}

{% step %}
### Attack

* Craft exploit:
  * Use an HTML template that causes a GET request (or otherwise avoids CSRF-protected method).
  * Replace YOUR-LAB-ID with the lab URL and set email to attacker-controlled value.
* Inject & Test:
  * Paste to Exploit Server Body, Store.
  * View exploit to test and confirm the email changed.
* Deliver:
  * Modify the payload to a different email, Store, Deliver to victim.
{% endstep %}
{% endstepper %}

<details>

<summary>Why the exploit works</summary>

* CSRF Token Bypass: The server only enforces tokens for POST requests and ignores GET requests for sensitive actions.
* Automatic submission causes the victim browser to issue the request that lacks the required CSRF token for POST.

</details>

Recommendation: Validate CSRF tokens for all state-changing methods; do not use GET for state-changing actions.

Example exploit:

```html
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
</form>
<script>
  document.forms[0].submit();
</script>
```

***

### Lab: CSRF where token validation depends on token being present

{% stepper %}
{% step %}
### Introduction

Web\_Pentest: The email change function is vulnerable because the server accepts requests when the CSRF token is missing (it only rejects when an invalid token is present).
{% endstep %}

{% step %}
### Vulnerability - Problem

* Source:
  * The server does not properly verify the request when the CSRF token is missing.
* Sink:
  * Hosting a malicious HTML form on an exploit server.
* Challenge:
  * Trick a victim into submitting the request.
{% endstep %}

{% step %}
### Payload & End-goal

Create a malicious HTML form that changes the victim's email to an attacker-controlled address.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Initial Test:
  * Login (example credentials: wiener:peter), go to Update Email and change it.
* Inspect:
  * Capture the request and send to Repeater.
  * Modify CSRF parameter → request rejected.
  * Remove CSRF parameter entirely → request succeeds → server does not enforce CSRF protection when the token is absent.
{% endstep %}

{% step %}
### Attack

* Craft exploit using an HTML template; replace YOUR\_LAB\_ID with the lab ID.
* Upload to Exploit Server Body and Store.
* Test by viewing the exploit and verifying the email was changed to attacker@example.com.
* Deliver to victim after changing to an email not matching your account.
{% endstep %}
{% endstepper %}

<details>

<summary>Why the exploit works</summary>

* The server incorrectly treats missing CSRF tokens as acceptable while rejecting incorrect tokens. Attackers can omit the token entirely to bypass the check.

</details>

Prevention: Always validate CSRF tokens; avoid using GET for state changes.

Exploit example:

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@example.com">
</form>
<script>
    document.forms[0].submit();
</script>
```

***

### Lab: CSRF where token is not tied to user session

{% stepper %}
{% step %}
### Introduction

Web\_Pentest: The application uses CSRF tokens, but they are not tied to user sessions. A token generated for one user (Wiener) can be reused to perform actions for another user (Carlos).
{% endstep %}

{% step %}
### Vulnerability - Problem

* Source:
  * The CSRF token isn't tied to the user session.
* Sink:
  * Reuse of CSRF token from different users.
* Challenge:
  * Tokens may be single-use; ensure a fresh one is used in the exploit.
{% endstep %}

{% step %}
### Payload & End-goal

Use a CSRF token from user A to change user B's email to an attacker-controlled address.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Initial Test:
  * Log in as Wiener in Burp's browser, change email to capture a CSRF token.
* Inspect:
  * Log in as Carlos in an incognito browser; capture his email-change request.
  * Replace Carlos's CSRF token with Wiener's token; if accepted, the token is not session-bound.
{% endstep %}

{% step %}
### Attack

* Craft an HTML template with:
  * action pointing to the change-email endpoint
  * hidden inputs: email (attacker-controlled) and csrf (CSRF-TOKEN-HERE captured from Wiener)
* Host on Exploit Server, Store, View to test and confirm Carlos's email changes.
* Deliver to victim after adjusting the email.
{% endstep %}
{% endstepper %}

Payload:

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@example.com">
    <input type="hidden" name="csrf" value="CSRF-TOKEN-HERE">
</form>
<script>
    document.forms[0].submit();
</script>
```

<details>

<summary>Why the exploit works — Key takeaways</summary>

* CSRF tokens must be tied to user sessions so tokens generated by one user cannot be used by another.
* Single-use tokens should be enforced and validated against the logged-in user.

</details>

Real-world impact: account takeover via email change, interception of notifications, password resets.

***

### Lab: CSRF where token is tied to non-session cookie

2024-12-01

{% stepper %}
{% step %}
### Introduction

Web\_Pentest: The application uses a CSRF token generation tied to a cookie named csrfkey, but that cookie is not tightly bound to the user's session. It is possible to inject cookies into the victim's browser (via reflected Set-Cookie behavior) and perform CSRF attacks.
{% endstep %}

{% step %}
### Vulnerability - Problem

* Source:
  * CSRF defense uses a csrfkey cookie and a matching CSRF token.
  * csrfkey is not strictly tied to the user session and can be injected into the victim's browser.
* Sink:
  * Cookie injection via a search endpoint that reflects Set-Cookie headers.
* Challenge:
  * Abuse the search functionality to inject your csrfKey into the victim's browser.
{% endstep %}

{% step %}
### End-goal

Use a CSRF token matching an injected cookie to change another user's email to one the attacker controls.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Initial Test:
  * Log in as Wiener, submit an email change to capture request.
* Inspect:
  * Intercept the email change request; note csrfkey cookie and CSRF token in request body.
  * In Repeater, modify csrfkey cookie to a random value → token rejected; modify session cookie → logged out. This shows csrfkey is independent of session.
{% endstep %}

{% step %}
### Attack

* Swap CSRF Token Between Accounts:
  * Log in as Carlos, capture his email-change request.
  * Replace Carlos's csrfkey and token with Wiener's → if accepted, csrfkey is reusable.
* Inject the Cookie:
  * Abuse the search function to reflect a Set-Cookie header:
    * Example payload: test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None
  * Send the request and check that csrfkey is injected into the victim's browser.
* Create the CSRF exploit:
  * Craft HTML with matching csrf token and an image tag to inject the cookie then submit the form.
  * Host on Exploit Server, Store, View to test, then Deliver to victim.
{% endstep %}
{% endstepper %}

Payload:

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@example.com">
    <input type="hidden" name="csrf" value="CSRF-TOKEN-HERE">
</form>
<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
```

<details>

<summary>Why the exploit works — Key lessons</summary>

* CSRF tokens must be tied to user sessions and validated against the session.
* Avoid relying on independent cookies for CSRF defense.
* Prevent cookie injection by validating inputs and not reflecting Set-Cookie headers from user-controlled data.
* Validate Origin/Referer as defense-in-depth.

</details>

Real-world impact: account takeover, interception of notifications, sensitive data exposure.

***

### Lab: CSRF where token is duplicated in cookie

2024-12-17

{% stepper %}
{% step %}
### Introduction

Web\_Pentest: The application uses a double-submit CSRF protection technique where a token is sent both as a cookie and in the request body. However, the server only checks that they match, not that the cookie originated from the server.
{% endstep %}

{% step %}
### Vulnerability - Problem

* Source:
  * The server verifies that the token in the request body matches the token in a csrf cookie.
  * It does not validate where the cookie originated.
* Sink:
  * Inject a fake csrf cookie into the victim's browser and craft a request using that fake token.
* Challenge:
  * Inject the fake token via a reflected Set-Cookie behavior and then submit a matching body token.
{% endstep %}

{% step %}
### End-goal

Change the victim's email using a fake token injected into their cookies.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Log in and change the email to capture a request.
* Observe that the CSRF token is sent in both the request body and the csrf cookie.
* The server only checks they match; if you inject a fake cookie and submit a matching body token, the server accepts it.
{% endstep %}

{% step %}
### Attack

* Inject fake csrf cookie via search endpoint:
  * Modify search term to include: test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None
  * Send request; this reflects a Set-Cookie header and injects the fake csrf cookie into the victim's browser.
* Craft an exploit HTML that uses csrf=fake in the body and submits the request.
* Host on Exploit Server, Store, View to test, then Deliver to victim.
{% endstep %}
{% endstepper %}

Payload:

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@example.com">
    <input type="hidden" name="csrf" value="fake">
</form>
<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" 
     onerror="document.forms[0].submit();">
```

<details>

<summary>Why the exploit works</summary>

* The  tag triggers the search endpoint with a payload that reflects a Set-Cookie header, injecting csrf=fake into the victim's cookies.
* The form uses csrf=fake in the request body; because the server only checks that cookie and body values match, it accepts the request.
* The image ensures cookie injection occurs before the form submission.

</details>

Real-world analogy: a bank using double-submit CSRF but not verifying cookie provenance could be tricked into accepting attacker-supplied tokens, enabling account takeover.

## Key preventative measures (summary)

* Always tie CSRF tokens to user sessions and validate them against the logged-in user.
* Ensure CSRF tokens are unique and single-use where possible.
* Validate CSRF tokens for all state-changing request methods (not just POST).
* Never use GET for state-changing operations.
* Do not reflect Set-Cookie headers from user-controlled input; validate inputs to prevent cookie injection.
* Use defense-in-depth: Origin/Referer checks, SameSite cookies, and additional server-side verification.

## Additional resources

* Use Burp Suite Engagement tools → Generate CSRF PoC for quick PoC generation.
* Test exploits on an exploit server instance in controlled lab environments before real-world testing.
