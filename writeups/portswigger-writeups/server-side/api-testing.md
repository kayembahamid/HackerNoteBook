# API testing

API enables software systems and applications to communicate and share data.

API vulnerabilities can undermine confidentiality, integrity, and availability.

* All dynamic websites are composed of APIs.
* Testing APIs that aren't fully used by the website front-end is a gem (RESTful and JSON APIs).
* Test for server-side parameter pollution — this can affect internal APIs.

***

## API recon

* Identify API endpoints (the location where an API receives requests about a specific resource on its server).

Example:

```
GET /api/books HTTP/1.1
Host: example.com
```

The API endpoint of this request is `/api/books`. This interacts with the API to retrieve a list of books from the library.

* Once you identify an endpoint, determine how to interact with it and construct valid HTTP requests to test the API.
* Find out:
  * Input data the API processes (required and optional parameters).
  * Types of requests the API accepts (supported HTTP methods and media formats).
  * Rate limits and authentication mechanisms.

***

## API documentation

APIs are usually documented to help developers use and integrate with them.

* Human-readable documentation: for developers.
* Machine-readable documentation: structured formats like JSON or XML for automation (integration, validation).
* API documentation is often publicly available — start recon by reviewing documentation.

### Discovering API documentation

Using the browser or automated crawlers you may find API documentation (sometimes hidden).

* Use the browser manually or use Burp Scanner to crawl the app.
* Look for endpoints that refer to API documentation:
  * `/api`
  * `/swagger/index.html`
  * `openapi.json`

If you identify a resource endpoint, investigate the base path (example: resource `/api/swagger/v1/users/123` → check `/api/swagger/v1`, `/api/swagger`, `/api`).

You can also discover common documentation paths using intruder.

***

## Lab: Exploiting an API endpoint using documentation

{% stepper %}
{% step %}
### Introduction

Target: Web\_Pentest600 — look for API endpoints.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester searches for vulnerable targets and looks for endpoints in the API documentation.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: login and delete other users.\
Payload: Recon via API documentation.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Login with credentials `wiener:peter`.
* Update the email address.
* In Proxy > HTTP history send `PATCH /api/user/wiener` to Repeater — note this retrieves credentials for `wiener`.
* Remove `/wiener` from the path and send `/api/user` — returns an error because no user identifier.
{% endstep %}

{% step %}
### Attack

* Remove `/user` and send `/api` — this retrieves API documentation.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Right-click the response and select "Show response in browser", copy the URL, paste into a browser to access the interactive documentation.
* To delete Carlos and solve the lab, use the interactive DELETE operation for user `carlos` and send the request.
{% endstep %}

{% step %}
### Notes

Last remarks.
{% endstep %}
{% endstepper %}

***

## Using machine-readable documentation

* Use automated tools to analyse machine-readable API documentation.
* Burp Scanner can crawl and audit OpenAPI docs.
* Check JSON or YAML documentation.
* Parse OpenAPI using tools like OpenParser, BaAp.
* Use Postman or SoapUI to test documented endpoints.

***

## Identifying API endpoints

* Gather information by browsing applications that use the API (worth doing even if you have docs).
* Use Burp Scanner to crawl the app.
* Investigate interesting attack surfaces via browser.
* Look for patterns that suggest API endpoints during crawls.
* Use JS Link Finder BApp or manually review JavaScript files in Burp.

***

## Interacting with API endpoints

* Use Burp Repeater to interact with endpoints and confirm hidden endpoints.
* Test changes to HTTP method and media type.
* Review error messages and other responses to construct valid requests.

***

## Identifying supported HTTP methods

HTTP methods specify the action on a resource:

* GET — retrieve data.
* PATCH — apply partial changes.
* OPTIONS — retrieve supported methods for a resource.

Examples:

* `GET /api/tasks` — list tasks.
* `POST /api/tasks` — create a task.
* `DELETE /api/tasks/1` — delete task 1.

Use built-in HTTP verb lists in Burp Intruder to cycle through methods.

Note: When testing different HTTP methods, target low-priority objects to avoid unintended consequences.

***

## Identifying supported content types

* Endpoints often expect specific formats. Behavior may vary with Content-Type.
* Changing Content-Type may:
  * Trigger errors that disclose useful information.
  * Bypass flawed defenses.
  * Exploit differences in processing logic (e.g., secure for JSON but vulnerable for XML).
* Modify the `Content-Type` header and reformat requests.
* Use Content Type Converter BApp to convert between XML and JSON.

***

## Lab: Finding and exploiting an unused API endpoint

{% stepper %}
{% step %}
### Introduction

Target: Web\_Pentest601 — look for hidden API endpoints.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester searches for targets that leak information in error messages (`content-Type`).
{% endstep %}

{% step %}
### Payload & End-goal

Goal: exploit a hidden API endpoint to buy an expensive item.\
Payload: HTTP methods used by RESTful APIs.
{% endstep %}

{% step %}
### Reconnaissance Plan

* In Burp Proxy > HTTP history, click a product and check for `/api/products/3/price`. Send to Repeater.
* Change method from GET to OPTIONS — response shows GET and PATCH allowed.
* Change from GET to PATCH — response: `Unauthorized` (requires authentication).
* Login with `wiener:peter`.
{% endstep %}

{% step %}
### Attack

* In HTTP history, check for `API/producta/1/price` and send to Repeater.
* Change method to PATCH — error: incorrect Content-Type, specifying `application/json`.
* Add `Content-Type: application/json` header and an empty JSON body `{}` — error: missing `price` parameter.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Add `{"price":0}` and send the request.
* Reload product page in browser — price changed to `$0.00`.
* Add the product to basket and place order.
{% endstep %}

{% step %}
### Notes

Last remarks.
{% endstep %}
{% endstepper %}

***

## Using Intruder to find hidden endpoints

* Once you have initial endpoints, use Intruder to uncover hidden endpoints. Example:
* Found `PUT /api/user/update`. Add a payload position to `/update` and use wordlists like `delete`, `add`.
* Use wordlists based on common API naming conventions.

***

## Finding hidden parameters

* During recon, you may find undocumented parameters. Try using them to change app behavior. Burp tools:
* Burp Intruder — use wordlists of common parameter names to add/replace parameters.
* Param Miner BApp — can guess many parameter names automatically, relevant to the app.
* Content discovery — discover content not linked from visible pages.

***

## Mass assignment vulnerabilities (auto-binding)

* Frameworks can bind request parameters to internal object fields, creating unintended parameters.
* This can result in the application supporting parameters that were never intended to be processed.

### Identifying hidden parameters

Examine objects returned by the API.

Example: PATCH request to update username/email:

```json
{
  "username": "wiener",
  "email": "wiener@example.com"
}
```

GET `/api/users/123` returns:

```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "isAdmin": "false"
}
```

This indicates `id` and `isAdmin` may be bound to the internal user object.

### Testing mass assignment vulnerabilities

Modify the PATCH request by adding `isAdmin`:

```json
{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": "false"
}
```

Send with invalid value:

```json
{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": "foo"
}
```

If behavior differs, the parameter may affect logic. Try setting `isAdmin` to `true`:

```json
{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": "true"
}
```

If no validation, `wiener` could be granted admin privileges—browse the app as `wiener` to check.

***

## Lab: Exploiting a mass assignment vulnerability

{% stepper %}
{% step %}
### Introduction

Target: Web\_Pentest602 — look for hidden mass assignment endpoints.
{% endstep %}

{% step %}
### Vulnerability — Problem

Pen-tester searches for vulnerable targets.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: Find & exploit mass assignment API endpoint to buy an expensive item.\
Payload: HTTP methods used by RESTful APIs.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Login with `wiener:peter`.
* Click product and add to basket.
* In Proxy > HTTP history, look for `/api/checkout` GET and POST.
  * GET contains same JSON structure as POST.
  * GET response includes `choosen_discount` (POST doesn't).
* Send `POST /api/checkout` to Repeater.
{% endstep %}

{% step %}
### Attack

* In Repeater, add `choosen_discount`:

```json
{
  "chosen_discount": {
    "percentage": 0
  },
  "chosen_products": [
    {
      "product_id": "1",
      "quantity": 1
    }
  ]
}
```

* Send request — no error. Changing `chosen_discount` to `X` causes an error (type validation).
{% endstep %}

{% step %}
### Exploit & Enumerate

* Change `chosen_discount.percentage` to `100` and send the request.
* Observe effect (discount applied).
{% endstep %}

{% step %}
### Notes

Last remarks.
{% endstep %}
{% endstepper %}

***

## Server-side parameter pollution (SSPP)

* Some APIs are internal and not directly internet-accessible.
* SSPP occurs when user input is embedded in a server-side request to an internal API without adequate encoding.
* Also called HTTP parameter pollution. It can be used to bypass WAFs.
* An attacker may manipulate or inject parameters to:
  * Override parameters.
  * Modify application behavior.
  * Access unauthorized data.
* Test all user input for parameter pollution:
  * Query parameters.
  * Form fields.
  * Headers.
  * URL path parameters.

***

## Testing for SSPP in the query string

* Place characters like `#`, `&`, `=` in input and observe the app response.

Example:

* Frontend request:

```
GET /userSearch?name=peter&back=/home
```

* Server-side internal API request:

```
GET /users/search?name=peter&publicProfile=true
```

### Truncating query strings

* URL-encode `#` to attempt truncation: Modified query:

```
GET /userSearch?name=peter%23foo&back=/home
```

Frontend will try to access:

```
GET /users/search?name=peter#foo&publicProfile=true
```

Review response to see if server-side query was truncated (e.g., absence of `publicProfile=true`).

### Injecting invalid parameters

* URL-encode `&` to add a second parameter:

```
GET /userSearch?name=peter%26foo=xyz&back=/home
```

Server-side:

```
GET /users/search?name=peter&foo=xyz&publicProfile=true
```

If response changes, injection may have succeeded.

### Injecting valid parameters

* Add a valid parameter known to the server:

```
GET /userSearch?name=peter%26email=foo&back=/home
```

Server-side:

```
GET /users/search?name=peter&email=foo&publicProfile=true
```

Check how the added parameter is parsed.

### Overriding existing parameters

* Inject a second parameter with same name:

```
GET /userSearch?name=peter%26name=carlos&back=/home
```

Server-side:

```
GET /users/search?name=peter&name=carlos&publicProfile=true
```

Behavior varies by server technology:

* PHP: last parameter wins.
* ASP.NET: combines both — may error.
* Node.js/Express: first parameter wins.

If override succeeds, you can try exploits like `name=administrator`.

***

## Lab: Exploiting SSPP in a query string

{% stepper %}
{% step %}
### Introduction

Target: Web\_Pentest603 — use URL query syntax to attempt to change a server-side request.
{% endstep %}

{% step %}
### Vulnerability — Problem

Using error messages to interpret how server-side API processes user input.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: exploit SSPP in query string to log in as administrator.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Trigger password reset for `administrator` with Burp running.
* Check Proxy > HTTP history for `POST /forgot-password` and referenced JS `/static/js/forgotPassword.js`.
* Send to Repeater and confirm consistency.
* Change `username` to `administratox` — response `Invalid username`.
* Add `&x=y` encoded: `username=administrator%26x=y` — response `Parameter is not supported` (internal API may have received injected parameter).
* Attempt truncation with `#`: `username=administrator%23` — response `Field not specified` (server-side query may include `field`).
* Add `&field=x#`: `username=administrator%26field=x%23` — response `Invalid field` (server recognizes injected field).
* Brute-force `field` values.
{% endstep %}

{% step %}
### Attack

* Send `POST /forgot-password` to Intruder.
  * Position payload in `field` value: `username=administrator%26field=§x§%23`.
  * Use payload list `server-side variable names`.
  * Start attack and review 200 responses containing username and email.
* Change `field` to `email`: `username=administrator%26field=email%23` — returns original response (valid).
* In JS `/static/js/forgotPassword.js`, password reset endpoint uses `reset_token`: `/forgot-password?reset_token=${resetToken}`.
* In Repeater, change `field` to `reset_token`: `username=administrator%26field=reset_token%23` — returns a password reset token.
{% endstep %}

{% step %}
### Exploit & Enumerate

* In browser, open `/forgot-password?reset_token=123456789`, set new password, login as administrator, go to Admin panel.
{% endstep %}

{% step %}
### Notes

Last remarks.
{% endstep %}
{% endstepper %}

***

## Testing SSPP in REST paths

* REST APIs may put parameters in the URL path (`/api/users/123`).
* Example where frontend does `GET /edit_Profile.php?name=peter` and server-side does `GET /api/private/users/peter`.
* Try adding traversal sequences: URL-encode `peter/../admin` as `peter%2f..%2fadmin` → server-side may normalise to `api/private/users/admin`.

***

## Lab: Exploiting SSPP in a REST URL

{% stepper %}
{% step %}
### Introduction

Target: Web\_Pentest603 — identify whether input is included in server-side URL path or query string.
{% endstep %}

{% step %}
### Vulnerability — Problem

Use path traversal sequences to attempt to change a server-side request and discover API documentation.
{% endstep %}

{% step %}
### Payload & End-goal

Goal: exploit SSPP in REST URL to log in as administrator.
{% endstep %}

{% step %}
### Reconnaissance Plan

* Trigger password reset for `administrator` with Burp.
* In Proxy > HTTP history note `POST /forgot-password` and `/static/js/forgotPassword.js`.
* Send POST to Repeater, test modified `username` values to determine if input is placed in the path:
  * `administrator%23` → `Invalid route` (input likely in path).
  * `administrator%3F` → `Invalid route`.
  * `./administrator` → original response (same path).
  * `../administrator` → `Invalid route` (invalid path).
{% endstep %}

{% step %}
### Attack

* Change `username` to `../%23` → `Invalid route`.
* Add more `../` sequences until `../../../../%23` → `Not found` (navigated outside API root).
* Add common API filenames:
  * `username=../../../../openapi.json%23` → returns error leaking endpoints, e.g. `/api/internal/v1/users/{username}/field/{field}` (indicates `field` parameter in URL).
{% endstep %}

{% step %}
### Exploit & Enumerate

* Update `username` to `administrator/field/foo%23` → invalid field error (API supports only `email`).
* Try `username=administrator/field/email%23` → original response.
* Inspect `/static/js/forgotPassword.js` for password reset param `passwordResetToken`.
* In Repeater, set `username=administrator/field/passwordResetToken%23` — may error if unsupported by current API version.
* Use the discovered `/api/` endpoint and change version: `username=../../v1/users/administrator/field/passwordResetToken%23` → returns password reset token.
* In browser, visit `/forgot-password?passwordResetToken=123456789`, set password, login as admin, go to Admin panel and delete `carlos`.
{% endstep %}

{% step %}
### Notes

Last remarks.
{% endstep %}
{% endstepper %}

***

## Testing SSPP in structured data formats

* Inject unexpected structured data into user inputs and check responses.

Example:

* Frontend: `POST /myaccount name=peter`
* Server-side translates to:

```
PATCH /users/7312/update {"name":"peter"}
```

If you can make frontend send:

```
POST /myaccount name=peter","access_level":"administrator
```

and server-side concatenates without adequate encoding, server may process:

```
PATCH /users/7312/update {"name":"peter","access_level":"administrator"}
```

This could grant administrator access.

Another example with JSON:

* Browser sends:

```json
POST /myaccount {"name": "peter"}
```

Server-side:

```json
PATCH /users/7312/update {"name":"peter"}
```

If you can make the browser send:

```json
POST /myaccount {"name": "peter\",\"access_level\":\"administrator"}
```

and input is decoded and merged into server-side JSON without encoding, access level could be changed.

***

## Testing with automated tools

* Use automated tools to speed up SSPP detection:
  * Burp Scanner.
  * Backslash Powered Scanner BApp to identify server-side injection.

***

## Preventing vulnerabilities in APIs

* Secure documentation if not intended to be public.
* Keep documentation up to date.
* Maintain full visibility of API attack surface.
* Apply an allowlist of permitted HTTP methods.
* Validate content types for requests/responses.
* Use generic error messages to avoid leaking information.
* Apply protective measures across all API versions.
* Use allowlist to define characters that don't need encoding.
* Encode user input before including in server-side requests.
* Validate that all input adheres to expected formats and structures.
