# Access control Vulnerabilities and privilege escalation

**Privilege escalation**

**The types of vulnerabilities that can arise with access control**

**How to prevent access control vulnerabilities**

## What is access control

* Who or what is authorised to perform actions or access resources.
* In web applications, access control is dependent on authentication and session management.
  * **Authentication**: confirms that the user is who they say they are.
  * **Session management**: identifies which subsequent HTTP requests are being made by that same user.
  * **Access control**: determines whether the user is allowed to carry out the action that they are attempting to perform.

The vulnerability is called _Broken access control_. Access control design decisions have to be made by humans so the potential for errors is high.

## Access control security model

* These are a set of access control rules that are independent of the technology or implementation platform.
* These can be implemented within operating systems, networks, database management systems, back office systems, application and web server software.

## Programmatic access control

* The matrix of user privileges is stored in a database or similar.
* Controls are applied programmatically with reference to this matrix.
* This includes roles, groups, individual users, collections, workflows.

## Discretionary access control (DAC)

* Access to a resource is based upon users or named groups of users.
* The owner of the resource or functions can assign or delegate access permissions to users.
* This model can become very complex to design and manage.

## Mandatory access control (MAC)

* Centrally controlled system of access control.
* Access to an object (a file or other resource) by a subject is constrained.
* Users and owners of resources have no capability to delegate or modify access rights.
* Associated with military clearance-based systems.

## Role-based access control (RBAC)

* Named roles are defined and access privileges are assigned to those roles.
* Users are then assigned to single or multiple roles.

## Vertical access controls

* Mechanisms restrict access to sensitive functionality to specific types of users.
* Different user types have access to different application functions:
  * admin = modify / delete any user's account
  * user = read / write
* Popular in business models to enforce business policies like separation of duties and least privilege.

## Horizontal access controls

* Mechanisms restrict access to resources to specific users.
* Different users have access to a subset of resources of the same type.
  * Example: a banking application allows a user to view transactions and make payments from their own accounts but not the accounts of other users.

## Context-dependent access controls

* Restrict access to functionality and resources based upon:
  * the state of the application
  * the user's interaction with it.
* Prevents a user performing actions in the wrong order (e.g., preventing cart modification after payment).

## Examples of broken access controls

These exist when a user can access resources or perform actions that they are not supposed to be able to.

### 1. Vertical privilege escalation

When a user gains access to functionality they are not permitted to access (e.g., a non-administrative user gaining admin access).

#### Unprotected functionality

* If the application doesn't enforce protection for sensitive functionality (example: administrator page linked from a user's page).
* Users can access administrative functions by browsing to the admin URL:
  * `https://insecure-website.com/admin`
* Disclosure of administrative URLs in `robots.txt`:
  * `https://insecure-website.com/robots.txt`
* Attackers can use wordlists to brute-force the location of sensitive functionality.

Lab: Unprotected admin functionality

{% stepper %}
{% step %}
### Vulnerability

This lab has an unprotected admin panel.

### End-goal

Delete user carlos.

### Analysis

* View the `robots.txt` by appending `/robots.txt` to the lab URL.
* Notice the `Disallow` line discloses the path to the admin panel.
* In the URL bar, replace `/robots.txt` with `/administrator-panel` to load the admin panel.
* Delete `carlos`.

### Payload

`/administrtor-panel`
{% endstep %}
{% endstepper %}

### Security by obscurity

* Sensitive functionality may be concealed by giving it a less predictable URL (e.g., `https://insecure-website.com/administrator-panel-yb556`).
* The application might leak the URL in JavaScript that constructs the UI.

```javascript
<script>
	var isAdmin = false;
	if (isAdmin) {
		...
		var adminPanelTag = document.createElement('a');
		adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556');
		adminPanelTag.innerText = 'Admin panel';
		...
	}
</script>
```

This script contains the admin URL for all users regardless of role.

Lab: Unprotected admin functionality with unpredictable URL

{% stepper %}
{% step %}
### Vulnerability

This lab has an unprotected admin panel.

### End-goal

Delete user `carlos`.

### Analysis

* Look for disclosures in the application.
* Review the home page's source using browser dev tools or Burp Suite.
* Some JavaScript discloses the admin panel URL.
* Load the admin panel and delete `carlos`.

### Payload

`/admin-hpat4k`
{% endstep %}
{% endstepper %}

### Parameter-based access control methods

* Some applications determine a user's access rights or role at login and then store this information in a user-controllable location:
  * hidden field, cookie, or query string parameter.
* The application makes access control decisions based on the submitted value:
  * `https://insecure-website.com/login/home.jsp?admin=true`
  * `https://insecure-webiste.com/login/home.jsp?role=1`
* By modifying these values, a user can access administrative functions.

Lab: User role controlled by request parameter

{% stepper %}
{% step %}
### Vulnerability

The lab has an admin panel at `/admin`, which identifies administrator using a forgeable cookie.

### End-goal

Access the admin panel and delete user `carlos`.\
Login credentials: `wiener:peter`.

### Analysis

* Try `/admin` and observe you can't access the admin panel.
* Browse the login page.
* In Burp Proxy, turn interception on and enable response interception.
* Complete and submit the login page and forward the result request in Burp.
* Observe the response sets the cookie `Admin=false`; change it to `Admin=true`.

### Payload

Open browser inspect tools and change the `Admin` cookie to `true`.
{% endstep %}
{% endstepper %}

Lab: User can be modified in user profile

{% stepper %}
{% step %}
### Vulnerability

The lab has an admin panel at `/admin`, accessible only to logged-in users with `roleid` of 2.

### End-goal

Access the admin panel and delete `carlos`.\
Login credentials: `wiener:peter`.

### Analysis

* Login and access the account page.
* Update the email associated with your account.
* Observe the response contains your `roleid`.
* Send the email submission request to Burp Repeater and add `"roleid":2`.
* The response shows your `roleid` has changed to 2.
* Browse to `/admin` and delete `carlos`.

### Payload

Add the role number to the email parameter and submit to change to admin.
{% endstep %}
{% endstepper %}

### Broken access control resulting from platform misconfiguration

* Access restrictions based on URLs and HTTP methods may be overridden by non-standard headers like `X-Original-URL` or `X-Rewrite-URL`.
* The front-end may restrict access based on the URL, but the backend may process an overridden URL from headers.

Example attack:

```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
```

Lab: URL-based access control can be circumvented

{% stepper %}
{% step %}
### Vulnerability

This website has an admin panel at `/admin`. The front end blocks direct access, but the backend supports `X-Original-URL`.

### End-goal

Access the admin panel and delete user `carlos`.

### Analysis

* Try to load `/admin` and observe you get blocked (response originates from front-end).
* Send the request to Burp Repeater.
* Change the URL in the request line to `/`.
* Add header `X-Original-URL: /invalid.` — the application returns `not found`, indicating backend processes that header.
* Change the header to `X-Original-URL: /admin`.
* Access admin and delete `carlos` by adding `?usernme=carlos` to the real query string.
* Optionally change `X-Original-URL` path to `/admin/delete`.

### Payload

Add header: `X-Original-URL: /admin`
{% endstep %}
{% endstepper %}

HTTP method issues: some sites tolerate different HTTP request methods for actions; attackers can switch methods (e.g., GET vs POST) to bypass platform-layer access control.

Lab: Method-based access control can be circumvented

{% stepper %}
{% step %}
### Vulnerability

This website implements access control partly based on the HTTP method of requests. Administrator credentials: `administrator:admin`.

### End-goal

Solve the lab by logging in with `wiener:peter` and exploiting flawed access controls to promote yourself to administrator.

### Analysis

* Log in with admin credentials and browse to the admin panel; promote `carlos` and send the HTTP request to Burp Repeater.
* Open a private/incognito window, log in with non-admin credentials.
* Attempt to re-promote `carlos` with the non-admin user by copying that user's session cookie into the Burp Repeater request.
* The response says `Unauthorised`.
* Change the method from `POST` to `POSTX` — observe the response changes.
* Convert request to `GET` and change the username parameter to your username; resend the request.

### Payload

Use a low-privilege user's cookie in the request and change the method from `POST` to `GET` to bypass method-based checks.
{% endstep %}
{% endstepper %}

### Broken access control resulting from URL-matching discrepancies

* Inconsistent capitalisation, suffix pattern matching, or trailing slashes can cause endpoints to be matched unexpectedly (e.g., `/admin/deleteUser.anything` mapping to `/admin/deleteUser`).
* Systems may treat `/admin/deleteUser` and `/admin/deleteUser/` differently, allowing bypass via trailing slash.

## 2. Horizontal privilege escalation

When a user gains access to another user's resources (e.g., by modifying an `id` parameter).

Note: This is an example of an insecure direct object reference (IDOR)—these arise when user-controlled parameter values are used to access resources or functions directly.

Lab: User ID controlled by request parameter

{% stepper %}
{% step %}
### Vulnerability

Horizontal privilege escalation on the user account page.

### End-goal

Obtain the API key for user `carlos` and submit the solution.\
Login: `wiener:peter`.

### Analysis

* Log in using the supplied credentials and go to your account page.
* The URL contains the username in the `id` parameter.
* Send the request to Repeater.
* Change the `id` parameter to `carlos`.
* Retrieve and submit the API key for `carlos`.

### Payload

Change the `id` parameter to a guessable username.
{% endstep %}
{% endstepper %}

Note: If the exploitable parameter is not predictable, the app might use GUIDs. Check if GUIDs are disclosed elsewhere in the application (e.g., user messages, reviews).

Lab: User ID controlled by request parameter, with unpredictable user IDs

{% stepper %}
{% step %}
### Vulnerability

Horizontal privilege escalation on the user account page where users are identified with GUIDs.

### End-goal

Find the GUID for `carlos`, retrieve his API key, and submit it.\
Login: `wiener:peter`.

### Analysis

* Find a blog post by `carlos` and click his profile—the URL contains his user ID; note it.
* Login as a normal user.
* Change the `id` parameter to the noted `carlos` user ID.
* Retrieve and submit the API key.

### Payload

Look for GUIDs for other users in the application. Use Burp proxy to intercept requests and supply the stolen user ID.
{% endstep %}
{% endstepper %}

Note: An application may be misconfigured such that it detects an unauthorized access and redirects to the login page, but the response body may still include some sensitive data.

Lab: User ID controlled by request parameter with data leakage in redirect

{% stepper %}
{% step %}
### Vulnerability

The lab leaks sensitive information in the body of a redirect response.

### End-goal

Obtain the API key for `carlos`.\
Login: `wiener:peter`.

### Analysis

* Login and go to your account page.
* Send the request to Burp Repeater and change the `id` parameter to `carlos`.
* The response is redirected to the home page but contains a body with `carlos`'s API key.

### Payload

Leaking the API key in the response. Use Burp Repeater to change the user and check the response body.
{% endstep %}
{% endstepper %}

### Horizontal to vertical privilege escalation

* Attacker compromises a more-privileged user (e.g., an administrator) by targeting their account via parameter tampering or other means.
* An admin account page might disclose a password or provide means to change it or access privileged functionality.

Lab: User ID controlled by request parameter with password disclosure

{% stepper %}
{% step %}
### Vulnerability

The lab's user account page contains the current user's existing password pre-filled in a masked input.

### End-goal

Retrieve the administrator's password, use it to delete `carlos`.\
Login: `wiener:peter`.

### Analysis

* Login and access the user account page.
* Change the `id` parameter in the URL to `administrator`.
* View the response in Burp; it contains the administrator's password.
* Login to the administrator account and delete `carlos`.

### Payload

Proxy the admin page to reveal the admin password in the response.
{% endstep %}
{% endstepper %}

## Insecure direct object references (IDOR)

* Occurs when an application uses user-supplied input to access objects directly; an attacker can modify the input to obtain unauthorized access.

Lab: Insecure direct object references

{% stepper %}
{% step %}
### Vulnerability

The lab stores user chat logs on the server file system and retrieves them using static URLs.

### End-goal

Find the password for user `carlos` and log into their account.

### Analysis

* Select the live chat tab, send a message, then select View transcript.
* Review the URL: transcripts are text files with incrementing numbers.
* Change the filename to `1.txt` and review the text; notice a password.
* Return to the main lab page and login using the stolen credentials.

### Payload

Proxy the `.txt` transcript URL, change the number, and inspect leaked data.
{% endstep %}
{% endstepper %}

## Access control vulnerabilities in multi-step processes

* Multi-step actions (capture inputs, review, confirm) can be vulnerable if some steps enforce access control and others do not.
* An attacker can skip steps and directly submit the final request with required parameters.

Lab: Multi-step process with no access control on one step

{% stepper %}
{% step %}
### Vulnerability

Admin panel has a flawed multi-step process for changing a user's role. Admin credentials: `administrator:admin`.

### End-goal

Log in as `wiener:peter` and promote wiener to administrator by exploiting flawed controls.

### Analysis

* Login with admin credentials and promote `carlos`; send the confirmation HTTP request to Burp Repeater.
* Login with non-admin credentials.
* Copy the non-admin user's session cookie into the Repeater request.
* Change the username to yours and replay the request.

### Payload

Replace the session cookie of a high-privileged user on the final confirmation step with a less-privileged user's session, and complete the process.
{% endstep %}
{% endstepper %}

## Referer-based access control

* Some applications base access control on the `Referer` header for subpages.
* The `Referer` header can be fully controlled by an attacker; forging it can allow direct requests to sensitive subpages.

Lab: Referer-based access control

{% stepper %}
{% step %}
### Vulnerability

The lab controls admin functionality based on the `Referer` header. Admin credentials: `administrator:admin`.

### End-goal

Log in as `wiener:peter` and promote wiener to administrator.

### Analysis

* Login with admin credentials, promote `carlos`, and send the HTTP request to Burp Repeater.
* Login with non-admin credentials.
* Browse to `/admin-roles?username=carlos&action=upgrade` — the request is unauthorized due to missing `Referer`.
* Copy the non-admin user's session cookie into the Repeater request.
* Change the username to yours and replay the request.

### Payload

Change the `Referer` header to the one used by admin to appear as if the request came from the admin interface.
{% endstep %}
{% endstepper %}

## Location-based access control

* Some websites enforce access controls based on geographic location (e.g., banking, media services).
* These can be circumvented using web proxies, VPNs, or manipulation of client-side geolocation.

## How to prevent access control vulnerabilities

{% hint style="success" %}
* Take a defense-in-depth approach.
* Never rely on obfuscation alone for access control.
* Unless a resource is intended to be publicly accessible, deny access by default.
* Whenever possible, use a single, application-wide mechanism for enforcing access controls.
* At code level, require developers to declare allowed access for each resource and deny by default.
* Thoroughly audit and test access control to ensure they work as designed.
{% endhint %}
