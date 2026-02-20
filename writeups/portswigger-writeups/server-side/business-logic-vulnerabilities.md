# Business logic vulnerabilities

## Business logic and logic flaws

Business logic refers to the set of rules that define how the application operates. These rules aren't directly related to a business domain in this context — they are the rules governing workflows, validation, and how different parts of an application interact.

Logic flaws are vulnerabilities that occur when users misuse the application or when developers make flawed assumptions about user behavior or application state. These vulnerabilities:

* Arise due to flawed assumptions about user behaviors or how components interact.
* Involve manipulating legitimate functionality rather than exploiting memory bugs or injections.
* Typically require human understanding of the application's workflows to detect and exploit.
* Are generally not detected by automated scanners — they are a great target for bug bounty hunters and manual testers.

Examples of logic-flaw behavior:

* Completing a transaction without following the intended purchase workflow.
* Passing unexpected values into server-side logic.

***

## How business logic vulnerabilities arise

* Design and development teams make flawed assumptions about how users interact with the app.
* These assumptions lead to inadequate server-side validation or the assumption that input is only supplied via a browser.
* Relying entirely on weak client-side controls allows attackers to bypass validations using intercepting proxies (e.g., Burp, ZAP).
* Complex systems with many interacting features are more likely to contain logic flaws — an attacker often needs to understand the whole application to combine functions in unexpected ways.
* Incorrect assumptions about how other components behave can open exploitable paths.

***

## Impact

* They increase the attack surface for other exploits.
* They can lead to stolen funds, fraud, unauthorized access, or other business-impacting events.

***

## Examples and labs

Learn from real-world cases and hands-on labs. Each lab below is presented as a stepper (Vulnerability → End goal → Analysis → Payload).

### Excessive trust in client-side controls

{% stepper %}
{% step %}
### Vulnerability

The lab doesn't validate user input server-side and relies on client-side controls.
{% endstep %}

{% step %}
### End-goal

Buy an item at a lower price than the allocated price (Lightweight 133t leather jacket).\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Use Burp while logging in and attempt to buy the leather jacket. The order is rejected due to insufficient store credit.
* Inspect HTTP history and study the order process.
* Add an item to the cart and observe a price parameter in `POST /cart`.
* Send the request to Repeater, change the price, and resend.
* Refresh the cart to confirm the price change.
* Repeat to any amount less than available credit.
{% endstep %}

{% step %}
### Payload

Change the price parameter to a minimal value to make the order succeed.
{% endstep %}
{% endstepper %}

***

### 2FA broken logic

{% stepper %}
{% step %}
### Vulnerability

Two-factor authentication implementation has flawed logic allowing account access for other users.
{% endstep %}

{% step %}
### End-goal

Access Carlos's account page.\
Credentials: wiener:peter\
Victim username: carlos
{% endstep %}

{% step %}
### Analysis

* Access the email server to receive 2FA code for wiener.
* Login and investigate the 2FA verification process.
* Observe `POST /login2` uses a `verify` parameter to determine which user is being accessed.
* Send `GET /login2` to Repeater and change `verify` to `carlos` to generate a temporary 2FA code for carlos.
* Submit an invalid 2FA code in the login page, then use Burp Intruder on `POST /login2`, set `verify=carlos`, and brute-force the `mfa-code` parameter.
* Load the 302 response in the browser and navigate to My account to solve the lab.
{% endstep %}

{% step %}
### Payload

Brute-force Carlos's 2FA code via Intruder while setting `verify=carlos`.
{% endstep %}
{% endstepper %}

***

### Failing to handle unconventional input

Context: If developers don't code for edge cases (e.g., negative quantities), unexpected behavior can occur. Example PHP logic that only checks numeric comparison:

{% code title="example.php" %}
```
```
{% endcode %}

```php
$transferAmount = $_POST['amount'];
$currentBalance = $user->getBalance();

if ($transferAmount <= $currentBalance) {
    // Complete the transfer
} else {
    // Block the transfer: insufficient funds
}
```

If an attacker sends `-1000`, the logic may incorrectly approve the transfer.

***

#### High-level logic vulnerability

{% stepper %}
{% step %}
### Vulnerability

Lab does not adequately validate input; purchase workflow can be manipulated to buy items at unintended prices.
{% endstep %}

{% step %}
### End-goal

Buy a Lightweight 133t leather jacket.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Run Burp, log in and add a cheap item to the cart.
* Inspect `POST /cart` and notice `quantity` parameter.
* Intercept and forward the request, change `quantity` to an arbitrary integer.
* Update cart quantities: select a high-price and a low-price item.
* Use negative quantity for the lower-priced item; total price decreases (negative amount).
* Repeat to manipulate total to desired value (stay above $0 to mimic normal purchase).
* Place the order to solve the lab.
{% endstep %}

{% step %}
### Payload

Set the lower-priced item quantity to a negative value to reduce the total price of the cart.
{% endstep %}
{% endstepper %}

***

#### Low-level logic flaw

{% stepper %}
{% step %}
### Vulnerability

Lab restricts quantity per request but fails to validate against integer overflow; allows numeric overflow to reduce price.
{% endstep %}

{% step %}
### End-goal

Buy a Lightweight 133t leather jacket.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* With Burp, attempt to buy the jacket; rejected due to insufficient credit.
* Send `POST /cart` to Repeater; note only 2-digit quantity allowed per request.
* Send request to Intruder, set the quantity parameter to 99 as a position.
* Use Null payloads with "Continue indefinitely" to increment quantity in many requests.
* As attack runs, refresh the cart page and observe price wrapping once integer max is exceeded.
* Generate enough payloads (e.g., 323) and use resource pool (max concurrent = 1).
* After attack, send a single `POST /cart` with 47 jackets; total becomes a large negative value.
* Add another item so price falls between $0 and $100; place order to solve lab.
{% endstep %}

{% step %}
### Payload

Use repeated large quantity additions to trigger integer overflow and cause negative totals, then place an order when total is favorable.
{% endstep %}
{% endstepper %}

***

#### Inconsistent handling of exceptional input

{% stepper %}
{% step %}
### Vulnerability

Account registration truncation and inconsistent validation allows registering an address that appears to be from a privileged domain.
{% endstep %}

{% step %}
### End-goal

Access the admin panel and delete the user carlos. You have access to the email client.
{% endstep %}

{% step %}
### Analysis

* Use Burp's content discovery to find `/admin`.
* `/admin` is restricted to `DontWannacry` users.
* On registration, use an email at `@YOUR-EMAIL-ID.web-security-academy.net` with a very-long-string (≥200 chars). Confirm and check the confirmation email.
* Observe the stored email is truncated to 255 characters.
* Register again with `very-long-string@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net` and craft the string so the `m` in `dontwannacry.com` ends at character 255.
* Confirm registration via the email link and log in — you now have admin access due to truncation logic.
{% endstep %}

{% step %}
### Payload

Register with a crafted long email so truncation results in a stored address ending in `@dontwannacry.com`.
{% endstep %}
{% endstepper %}

***

### Making flawed assumptions about user behavior

* Trusted users may become untrusted or lose privileges.
* Business and security controls must be applied consistently across the application.

#### Inconsistent security controls

{% stepper %}
{% step %}
### Vulnerability

Flawed logic allows arbitrary users to access admin functionality by switching email to a privileged domain.
{% endstep %}

{% step %}
### End-goal

Access the admin panel and delete the user carlos. You have access to the email client.
{% endstep %}

{% step %}
### Analysis

* Discover `/admin` via Burp engagement tools.
* Register with `anything@your-email-id.web-security-academy.net`.
* Confirm registration via email, log in, and change your email address to an `@dontwannacry.com` address.
* After changing the email, you gain access to the admin panel.
{% endstep %}

{% step %}
### Payload

Change your email to `@dontwannacry.com`.
{% endstep %}
{% endstepper %}

***

### Users won't always supply mandatory input

* Browsers may prevent missing inputs, but attackers can tamper with parameters in transit.
* Presence/absence of a parameter can cause application to execute different code paths.
* Try removing parameters, deleting names and values, or changing cookies and following multi-stage workflows to observe effects.

#### Weak isolation on dual-use endpoint

{% stepper %}
{% step %}
### Vulnerability

The endpoint assumes a user's privilege based on input; removing parameters allows privilege escalation.
{% endstep %}

{% step %}
### End-goal

Gain admin access and delete the user carlos.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Log in and change your password while proxying with Burp.
* Send `POST /my-account/change-password` to Repeater and remove the `current-password` parameter entirely.
* Observe you can change the password without supplying the current one.
* The target user is determined by the `username` parameter. Set `username=administrator` and resend.
* Logout and log in as administrator using the new password.
{% endstep %}

{% step %}
### Payload

Delete the `current-password` parameter and set `username=administrator`.
{% endstep %}
{% endstepper %}

***

#### Password reset broken logic

{% stepper %}
{% step %}
### Vulnerability

Password reset token is not validated when submitting a new password.
{% endstep %}

{% step %}
### End-goal

Reset Carlos's password, log in to his account, and access his My account page.\
Credentials: wiener:peter; victim username: carlos
{% endstep %}

{% step %}
### Analysis

* Use the "Forgot your password" flow and inspect the reset email: token is included as a URL query parameter.
* When submitting new password (`POST /forgot-password?temp-forgot-password-token`), the username is a hidden input.
* Send the request to Repeater and delete the token value in both the URL and body — the reset still works, showing token isn't verified on submission.
* Request a new reset, send the `POST` to Repeater, delete the token, change `username` to `carlos`, set a new password, and submit.
* Login as Carlos using the new password.
{% endstep %}

{% step %}
### Payload

Delete `temp-forgot-password-token` in URL and body, change `username` to an existing user, and set a new password.
{% endstep %}
{% endstepper %}

***

### Users won't always follow the intended sequence

* Applications assume users follow predefined workflows; skipping steps or reordering can open vulnerabilities (e.g., 2FA bypasses).

#### 2FA simple bypass

{% stepper %}
{% step %}
### Vulnerability

Two-factor authentication can be bypassed by navigating directly to authenticated pages after login prompt.
{% endstep %}

{% step %}
### End-goal

You have valid credentials but lack the victim's 2FA code. Bypass 2FA to access victim account.\
Credentials: wiener:peter; victim: carlos:montoya
{% endstep %}

{% step %}
### Analysis

* Log into your account; 2FA code is emailed to you. Note the account page URL.
* Log out and attempt to log in with victim credentials. When prompted for 2FA, manually change the URL to `/my-account`.
* The application may grant access despite not completing the 2FA step.
{% endstep %}

{% step %}
### Payload

Navigate directly to the account page URL after hitting the 2FA prompt.
{% endstep %}
{% endstepper %}

***

### Making assumptions about the sequence of events

* Use an intercepting proxy (Burp) to forward, drop, or replay requests out-of-order to force the application into unexpected states.

#### Insufficient workflow validation

{% stepper %}
{% step %}
### Vulnerability

The purchasing workflow assumes a particular sequence; order confirmation can be triggered without proper checkout validation.
{% endstep %}

{% step %}
### End-goal

Buy a Lightweight 133t leather jacket.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Log in and buy a cheap item you can afford.
* Observe `POST /cart/checkout` redirects to an order confirmation page.
* Send `GET /cart/order-confirmation?order-confirmation=true` to Repeater and add the leather jacket to the basket.
* Resend the order confirmation request in Repeater; observe the order completes without deducting cost from store credit.
{% endstep %}

{% step %}
### Payload

Buy a low cost item and abuse repeated/altered requests to complete checkout for a high price item without proper deduction.
{% endstep %}
{% endstepper %}

***

#### Authentication bypass via flawed state machine

{% stepper %}
{% step %}
### Vulnerability

Login process assumes sequential state machine; dropping requests causes default role assignment.
{% endstep %}

{% step %}
### End-goal

Bypass login to gain admin access and delete carlos.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Complete login where you must select a role before reaching home.
* Identify `/admin` via content discovery.
* Intercept and forward `POST /login`; the next request is `GET /role-selector`. Drop this role-selector request.
* Visit the home page — role defaults to `administrator`.
* Access `/admin` and delete carlos.
{% endstep %}

{% step %}
### Payload

Prevent the application from reaching the role selection step by intercepting/dropping the request so the app defaults to administrator.
{% endstep %}
{% endstepper %}

***

### Domain-specific flaws

* Flaws tied to the domain/purpose of the site (e.g., discount logic, coupon stacking, gift cards).
* Watch for any situation where prices or sensitive values are adjusted or computed.

#### Flawed enforcement of business rules

{% stepper %}
{% step %}
### Vulnerability

Purchasing workflow allows repeated/alternating coupon application leading to unintended discounts.
{% endstep %}

{% step %}
### End-goal

Buy a Lightweight 133t leather jacket.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Login and check coupon codes (e.g., NEWCUST5 and SIGNUP30).
* Add the jacket to cart and apply both coupons.
* Applying same code twice is rejected, but alternating codes may bypass controls.
* Alternate uses of codes can reduce total below available store credit.
{% endstep %}

{% step %}
### Payload

Alternate between coupon codes to reduce the total repeatedly.
{% endstep %}
{% endstepper %}

***

#### Infinite money logic flaw (gift card automation)

{% stepper %}
{% step %}
### Vulnerability

Gift card redemption and checkout logic can be automated to create unlimited store credit.
{% endstep %}

{% step %}
### End-goal

Automate buying and redeeming gift cards to accrue enough credit to buy the jacket.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Sign up for newsletter to get `SIGNUP30`.
* Buy a $10 gift card, add to basket, and apply coupon to get discount.
* Redeem the gift card on My account to add $3 credit (example).
* Use Burp's macro and session handling to automate the sequence:
  * Create a macro encompassing requests: `POST /cart`, `POST /cart/coupon`, `POST /cart/checkout`, `GET /cart/order-confirmation?order-confirmed=true`, `POST /gift-card`.
  * Configure macro to extract the generated gift card code from the order confirmation and feed it into `POST /gift-card`.
  * Test macro, then send `GET /my-account` to Intruder using Null payloads (generate many payloads) and a resource pool with max concurrent = 1 to automate many redemptions.
* This yields many small credits that sum to a large balance.
{% endstep %}

{% step %}
### Payload

Automate gift-card purchase and redemption (using Burp macros and Intruder) to accumulate credit.
{% endstep %}
{% endstepper %}

***

### Providing an encryption oracle

When user-controlled input is encrypted and the ciphertext is exposed to users, the site provides an "encryption oracle." An attacker can use it to create valid encrypted inputs and potentially decrypt values by using application behavior — enabling privilege escalation or forging authenticated cookies.

#### Authentication bypass via encryption oracle

{% stepper %}
{% step %}
### Vulnerability

The site exposes an encryption oracle: user-controlled input is encrypted and returned in a cookie; another endpoint will decrypt and reflect the plaintext.
{% endstep %}

{% step %}
### End-goal

Exploit the oracle to craft a `stay-logged-in` cookie for `administrator` and delete carlos.\
Credentials: wiener:peter
{% endstep %}

{% step %}
### Analysis

* Log in with "stay logged in" enabled and post a comment. Study the requests/responses.
* Observe `stay-logged-in` cookie is encrypted.
* Submit a comment with an invalid email; the response sets an encrypted `notification` cookie and reflects `invalid email address: your-invalid-email` in the error.
* Use the application to (a) encrypt arbitrary input via the `POST /post/comment` request (obtain a corresponding `notification` cookie), and (b) use the endpoint that reflects input (with the `notification` cookie) to decrypt arbitrary ciphertext.
* In Repeater, use one request named `encrypt` and one named `decrypt`. Use `encrypt` to get ciphertext for `administrator:timestamp` and `decrypt` to reveal decrypted plaintext.
* Remove the `invalid email address:` prefix by editing ciphertext in Burp Decoder and Repeater (careful block-based encryption/padding).
* Adjust prefix length and padding so deleting bytes aligns to 16-byte blocks.
* Replace `stay-logged-in` cookie with your crafted ciphertext and send request: you become administrator.
* Visit `/admin/delete?username=carlos` to solve the lab.
{% endstep %}

{% step %}
### Payload

Create a crafted ciphertext for `administrator:timestamp` using the encryption endpoint and manipulate block alignment/padding so that removing the automatic prefix yields a valid `stay-logged-in` value. Replace the `stay-logged-in` cookie with this ciphertext.
{% endstep %}
{% endstepper %}

***

## How to prevent business logic vulnerabilities

* Understand the application domain thoroughly — developers and testers should know how the app is supposed to behave.
* Avoid implicit assumptions about user behavior or the behavior of other components.
* Apply consistent business rules and security controls across the application.
* Perform robust server-side validation (do not rely on client-side checks).
* Write clear, maintainable code so intended behavior and checks are obvious.
* Model workflows and edge cases, and create tests for unconventional inputs, sequence deviations, and multi-component interactions.
* Conduct manual security testing with an understanding of the domain, and incorporate threat modeling focused on logic flaws.

