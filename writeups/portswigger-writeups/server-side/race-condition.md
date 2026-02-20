# Race Condition

This vulnerability is related to [Business logic vulnerabilities](../../../bugbounty/bugbounty-methodology.md#business-application-logic-bugs)

* These occur when website processes requests concurrently without adequate safeguards.
* Multiple distinct threads interacting with the same data at the same time can result in collisions that cause unintended behaviour.
* An attacker uses carefully timed requests to cause collisions and exploit unintended behaviour (race condition).
* The time window during which this collusion can occur is called the race window — it can be a fraction of a second between two interactions with the database.

This collusion is what we call Race window — could be a fraction of a second between two interactions with the database.

## Limit overrun race conditions

Example scenario: promotional code in an online store / checkout for one-time discount on the order.

Typical steps performed by the server:

* Check that you haven't already used this code.
* Apply the discount to the order total.
* Update the record in the database to reflect that you've now used this code.

Applying the discount code twice at the same time can cause a race condition:

* The application can enter a sub-state (entered and then exits before request processing completes).
* The substate begins when the server starts processing the first request and ends when it updates the database indicating you have already used the code.
* This introduces a small race window during which you can repeatedly reclaim the discount as many times as you like.

Note: Limit overruns are subtypes of "Time-of-check to Time-of-use" (TOCTOU) flaws.

Kinds of attacks:

* Redeeming a gift card multiple times
* Rating a product multiple times
* Withdrawing or transferring cash in excess of your account balance
* Reusing a single CAPTCHA solution
* Bypassing an anti-brute-force rate limit

***

## Detecting and exploiting overrun race conditions with Burp Repeater

* Identify a single-use or rate-limited endpoint with a security impact or useful purpose.
* Issue multiple requests to this endpoint in quick succession.

The challenge is timing the requests so two race windows line up to cause a collision. This window is in milliseconds.

* Various uncontrollable factors can affect when the server processes each request and in which order.
* Using Burp Suite 2023.9 (or later) can help by sending requests in groups in parallel via Repeater.

***

{% stepper %}
{% step %}
### Lab: Limit overrun race conditions — walkthrough

#### Lab introduction

Web\_Pentest200: Pen-tester finds a website with a race condition.

#### Vulnerability / Problem

The site enables purchasing items for an unintended price due to a race condition.

#### Payload & End-goal

Goal: buy an item at a cheaper price than intended.

#### Reconnaissance plan

* Login as a normal user.
* Buy the cheapest item with a discount code.
* Study the purchase flow and shopping cart mechanism.
* Identify endpoints related to the cart in Burp History:
  * `POST /cart` adds items to the cart.
  * `POST /cart/coupon` applies the discount code.
* Confirm cart state is stored server-side (test `GET /cart` with and without session cookie).
* Determine if there is a race window between applying the discount and database update.

#### Attack

* Ensure no discount in cart.
* Send `POST /cart/coupon` to Repeater.
* Add the tab to a group and create \~19 duplicates.
* Send the group of requests in sequence (separate connections) and observe responses.
* The first usually succeeds; others are rejected with "Coupon already applied".

#### Exploit

* Remove the discount from the cart.
* Send the same group of requests in parallel.
* If successful, multiple requests may indicate the code was applied multiple times.
* Refresh the cart to confirm multiple 20% reductions applied.

#### Enumerate

* Add an expensive item to the cart.
* Resend the group of `POST /cart/coupon` in parallel and refresh cart.
* If order total falls below remaining store credit, attempt purchase.

#### Mitigate

* Last remarks (see general mitigations later).
{% endstep %}
{% endstepper %}

***

## Detecting and exploiting limit overrun race conditions with Turbo Intruder

* Turbo Intruder (BApp store) can be used to send many requests with controlled timing using Python.
* Single-packet attacks require HTTP/2 and using `engine=Engine.BURP2` and `concurrentConnections=1`.
* Use the `gate` argument to group requests and `engine.openGate()` to release them simultaneously.

Example Turbo Intruder script snippet:

{% code title="turbo-queue.py" %}
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    # queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    # send all requests in gate '1' in parallel
    engine.openGate('1')
```
{% endcode %}

***

{% stepper %}
{% step %}
### Lab: Bypassing rate limits via race conditions — walkthrough

#### Lab introduction

Web\_Pentest201: Pen-tester finds a site using rate limiting to defend against brute-force.

#### Vulnerability / Problem

Bypass per-username rate limits via race conditions.

#### Payload & End-goal

Goal: brute-force admin password (use list of common passwords).

#### Reconnaissance plan

* Create two valid users.
* Observe rate limit behavior (e.g., 3 attempts per username).
* Confirm rate limit is enforced per-username and stored server-side.
* There may be a race window between submitting a login attempt and incrementing the failed-attempt counter.

#### Attack (Repeater)

* Find an unsuccessful `POST /login` in proxy history and send to Repeater.
* Duplicate the tab to create \~19 copies in a group.
* Send the group in sequence; observe locking behavior after three attempts.

#### Exploit

* Send the group in parallel.
* If timed well, more than three attempts receive normal "Invalid username and password" responses before account lock triggers.

#### Enumerate (Turbo Intruder)

* Highlight the `password` value and send to Turbo Intruder.
* Mark the password parameter as payload position.
* Use a single-packet attack template, assign `wordlists.clipboard` for passwords, and launch.
* Inspect results for successful login responses (e.g., 302), note corresponding password, wait for lock reset, then log in.

#### Mitigate

* Study responses, repeat carefully, and note successful credentials if any.
{% endstep %}
{% endstepper %}

Example Turbo Intruder single-packet template (concept):

{% code title="turbo-passwords.py" %}
```python
def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard
    
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
```
{% endcode %}

***

## Hidden multi-step sequences

* A single request may initiate a multi-step sequence behind the scenes.
* Applications pass through different sub-states before exiting the request process.
* Identifying multiple HTTP requests that interact with the same data can allow you to abuse sub-states and expose time-sensitive logic flaws.

Example: Flawed multi-factor authentication (MFA) workflow:

* Code snippet showing vulnerable flow:

```python
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True
    # generate and send MFA code to user
    # redirect browser to MFA code entry form
```

* If state changes are not atomic, forced browsing or race windows can bypass MFA.

***

### Methodology for testing race conditions

{% stepper %}
{% step %}
### 1 — Predict potential collisions

* Testing every endpoint is impractical. Map the target site to reduce endpoints to test:
  * Is this endpoint security-critical?
  * Is there collision potential? Successful collisions typically need two or more requests that operate on the same record.
* Example: variations of a password reset implementation — requesting parallel resets for different users or using the same session ID for both.&#x20;
{% endstep %}

{% step %}
### 2 — Probe for clues

* Benchmark how the endpoint behaves under normal conditions.
* Use Burp Repeater grouping and "Send group in sequence" (separate connections) to observe timings.
* Use the single-packet attack or last-byte sync (if HTTP/2 not supported), or Turbo Intruder to reduce jitter.
* Look for deviations from benchmark behaviour in responses or side-effects (e.g., emails, app changes).
{% endstep %}

{% step %}
### 3 — Probe for concept

* Advanced race conditions can produce unique primitives. Think structurally about impact — the maximum impact might not be obvious and may require modelling the application's state transitions.
{% endstep %}
{% endstepper %}

***

## Multi-endpoint race conditions

* Classic example in online stores:
  * Add items to basket -> pay -> add more items -> force-browse to order confirmation.
* Vulnerability occurs when payment validation and order confirmation are performed during the process of a single request.
* You can add more items during the race window between payment validation and order confirmation.

### Aligning multi-endpoint race windows

* Lining up race windows across different endpoints is challenging, even with single-packet technique.
* Two delaying factors:
  * Delays from network architecture (e.g., front-end server establishing backend connection, protocol used).
  * Endpoint-specific processing time variability.

Connection warming: send inconsequential requests first to smooth backend connection delays (e.g., add a `GET /` first in Repeater and send in sequence over single connection). If warming reduces variability, then backend warm-up was the issue.

***

{% stepper %}
{% step %}
### Lab: Multi-endpoint race conditions — walkthrough

#### Lab introduction

Web\_Pentest202: site with a purchasing flow that contains a race condition enabling unintended prices.

#### Vulnerability / Problem

Exploit multi-endpoint race conditions in purchasing flow.

#### Payload & End-goal

Goal: purchase an item at an unintended price (Burp Suite 2023.9+).

#### Reconnaissance plan

* Create two valid users. Login and purchase a gift card to study the flow.
* Identify cart endpoints (`POST /cart`, `POST /cart/checkout`).
* Confirm cart state is session-keyed (`GET /cart` with/without cookie).
* Note that order validation and confirmation occur within a single request/response, implying a race window.

#### Attack

* Send both `POST /cart` and `POST /cart/checkout` to Repeater and group them.
* Send the two requests in sequence over a single connection repeatedly; observe the first often takes longer.
* Add `GET /` to warm the connection; the latter requests complete in a smaller window.
* Modify `POST /cart` to add product ID 1 and test—order should be rejected for insufficient funds.

#### Exploit & Enumerate

* Remove item, add another gift card, and send requests in parallel.
* If you get a 200 for checkout, confirm success and enumerate further attempts to exploit.

#### Notes

* If inconsistent timing persists even with single-packet, backend delays may interfere — Turbo Intruder may work better (use warming requests followed by attack requests).
{% endstep %}
{% endstepper %}

***

## Abusing rate or resource limits

* If connection warming doesn't help, you can:
  * Introduce a short client-side delay using Turbo Intruder to split the attack across multiple TCP packets (avoid single-packet).
  * Send many dummy requests to trigger server-side rate/resource limits, then launch the actual attack.

***

## Single-endpoint race conditions

* Sending parallel requests with different values to the same endpoint can trigger race conditions.
* Example: password reset mechanism that stores userID and reset token in session.
  * Send two parallel password reset requests from the same session with two different usernames.
  * Final state might store victim userID but the valid reset token sent to the attacker:
    * session\['reset-user'] = victim
    * session\['reset-token'] = 1234

Note: This requires the operations to occur in the right order and may need multiple attempts or luck. Email-based workflows are good targets.

***

{% stepper %}
{% step %}
### Lab: Single-endpoint race conditions — walkthrough

#### Lab introduction

Web\_Pentest203: site where the email-change feature has a race condition.

#### Vulnerability / Problem

Allows associating an arbitrary email with your account via race.

#### Payload & End-goal

Goal: identify a race condition that allows claiming an arbitrary email address.

#### Reconnaissance plan

* Login and attempt to change your email to something like anything@email.net.
* A confirmation email is sent with a unique token link.
* Confirm the site stores a single pending email (new submissions overwrite existing pending email).
* There's a potential collision between kicking off an email send and updating the pending email.

#### Attack

* Send `POST /my-account/change-email` to Repeater and create \~19 duplicates.
* Modify each request to use different email addresses (`test1@`, `test2@`, ...).
* Send sequence (one by one) and note one confirmation email per change.
* Send the group in parallel; observe confirmation emails where the recipient and pending email don't match, indicating a race.

#### Exploit & Enumerate

* Create a group with two copies of `POST /my-account/change-email`.
* Set one email to your address and the other to `admin@domain.net`.
* Send in parallel:
  * If a confirmation email body shows your address but the recipient is admin (or vice versa), use the confirmation link as appropriate to change account email and access admin features.

#### Notes

* Success depends on timing and repeated attempts.
{% endstep %}
{% endstepper %}

***

## Session-based locking mechanisms

* Some frameworks attempt to prevent accidental data corruption by locking requests per session.
* PHP's native session handler typically processes one request per session at a time.
* If you see this behaviour, try sending each request with different session tokens to bypass single-session locking.

***

## Partial construction race conditions

* Many applications create objects in multiple steps, leaving temporary middle states that are exploitable.
* Example: user registration that creates the user record then sets the API key with a separate statement — there can be a short window where the user exists but the API key is uninitialised.
* During the race window, an attacker may inject input that matches the uninitialised value (empty string, null) to bypass checks.

Framework specifics:

* PHP: `param[]=foo` → `param=['foo']`, `param[]` → `param=[]`.
* Ruby on Rails: a parameter key with no value can render as `nil`.

Example HTTP (possible exploit during race window):

```http
GET /api/user/info?user=victim&api-key[]= HTTP/2
Host: vulnerable-website.com
```

Note: Similar collisions with passwords are possible, but because passwords are hashed you must inject a value that results in the same hash as the uninitialised value.

***

{% stepper %}
{% step %}
### Lab: Partial construction race conditions — walkthrough

#### Lab introduction

Web\_Pentest203: site where the user registration mechanism has a race condition.

#### Vulnerability / Problem

Allows bypassing email verification and registering with an arbitrary email address you control.

#### Payload & End-goal

Goal: exploit race condition to create an account (use Burp Suite 2023.9+ and Turbo Intruder).

#### Reconnaissance plan

* Study registration mechanism; you can only register with `@domain.shop` emails and must confirm via email.
* In Burp, find `/resources/static/users.js` which generates the confirmation form (notice final confirmation is `POST /confirm?token=...`).
* Craft confirmation requests in Repeater and test token parameter variants:
  * arbitrary token → `incorrect token:<YOUR-TOKEN>`
  * missing token → `Missing parameter: token`
  * empty token → `Forbidden`
  * `token[]` (empty array) → `Invalid token: Array` — this suggests the server treats empty array differently and may match an uninitialised token.

#### Attack

* Send `POST /register` to Repeater and experiment.
* Create a group with the `POST /register` and a crafted `POST /confirm?token[]=`.
* Send sequentially and in parallel; note confirmation is often processed quicker than registration.

#### Exploit & Enumerate (Turbo Intruder)

* Use Turbo Intruder to queue one registration request and many confirmation requests released together (gated).
* Strategy:
  * Make `username` a payload placeholder (`%s`), use a fixed password and `@domain.shop` email.
  * For each attempt, queue one registration and many confirmation requests (same gate).
  * `openGate()` to release them simultaneously.
* Inspect results for 200 responses to `POST /confirm?token[]` that indicate successful registration confirmation.
* Use the discovered username and password to login and access privileged areas.

#### Mitigate

* (See general mitigations section below.)
{% endstep %}
{% endstepper %}

Example Repeater / Turbo Intruder request template and script are included in the original content (kept as-is).

***

## Time-sensitive attacks

* Race techniques that produce requests with precise timing can reveal other vulnerabilities where non-cryptographic randomness is used (e.g., timestamps as tokens).
* Example: password reset tokens generated from timestamps — two resets at the same timestamp may yield identical tokens.

{% stepper %}
{% step %}
### Lab: Exploiting time-sensitive vulnerabilities — walkthrough

#### Lab introduction

Web\_Pentest204: site with a password reset mechanism (not necessarily a race condition).

#### Vulnerability / Problem

The password reset token generation uses a predictable input (timestamp), which can be exploited with carefully timed requests.

#### Payload & End-goal

Goal: obtain a valid password reset token for a target user (requires a valid account).

#### Reconnaissance plan

* Submit password reset requests multiple times and inspect emails/tokens.
* Check token length, variability, and whether tokens change each time.
* Duplicate the reset request and send in parallel to see if requests are processed sequentially.

#### Attack

* If the site uses PHP (session locking), process one request per session. Remove the session cookie from one `GET /forgot-password` to obtain a new session/cookie and CSRF token for a second session.
* Send two `POST /forgot-password` requests in parallel from different sessions.
* When response times match, the two confirmation emails may contain identical tokens — indicating a timestamp or predictable state in token generation.

#### Exploit & Enumerate

* If two users receive the same token, change one request's username to the targeted user and resend in parallel.
* If successful, a confirmation email with a token appears for the target. Use the token to reset password and log in.

#### Mitigate

* Use cryptographically secure randomness for token generation and avoid predictable inputs (timestamps, counters) alone.
{% endstep %}
{% endstepper %}

Note: you may need to try a few times to align server processing timestamps.

***

## How to prevent race condition vulnerabilities

Goals: eliminate sub-states and make sensitive endpoints atomic.

Recommendations:

1. Avoid mixing data from different storage places.
2. Ensure sensitive endpoints make state changes atomically using datastore concurrency features (use a single database transaction to check and update).
3. Use datastore integrity features (e.g., uniqueness constraints) as defense-in-depth.
4. Don't rely on one storage layer (e.g., sessions) to secure another (e.g., database).
5. Ensure session handling keeps sessions internally consistent — avoid updating session variables individually rather than in a batch. ORMs should manage transactions correctly.
6. Where appropriate, consider avoiding server-side state and push state client-side securely (e.g., encrypted JWTs) if it fits the architecture.
