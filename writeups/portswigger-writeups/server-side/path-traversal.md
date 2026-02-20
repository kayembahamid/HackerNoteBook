# Path Traversal

## webhacking

## What is path traversal?

* It's also known as directory traversal.
* These vulnerabilities enable an attacker to read arbitrary files on the server that is running an application:
  * Application code and data
  * Credentials for back-end systems
  * Sensitive operating system files
* An attacker may also be able to write arbitrary files on the server.
* The attacker can modify application data or behavior and ultimately take full control of the server.

## Reading arbitrary files via path traversal

* Example: a shopping app displays images for sale. The HTML used to load an image:

```html
<img src="/loadingImage?filename=218.png">
```

* The loaded image URL takes a filename parameter and returns the contents of the specified file.
* Image files are stored on disk in `/var/www/images/`.
* To return an image, the application appends the requested filename to the base directory and uses a filesystem API to read the file contents.
* The path for a normal request:

```
/var/www/images/218.png
```

* This application implements no defence against path traversal attacks. An attacker can request the following URL to retrieve `/etc/passwd`:

```
insecure-website.com/loadImage?filename=../../../etc/passwd
```

* The application reads from:

```
/var/www/images/../../../etc/passwd
```

* The sequence `../` steps up one level in the directory structure. Three consecutive `../` sequences step up from `/var/www/images/` to the filesystem root, yielding:

```
/etc/passwd
```

* On Unix-based systems, `/etc/passwd` contains details of registered users on the server.
* On Windows, both `../` and `..\` are valid directory traversal sequences. Example:

```
https://insecure-webiste.com/loadImage?filename=..\..\..\windows\win.ini
```

Lab: File path traversal, simple case

{% stepper %}
{% step %}
### Vulnerability

This lab contains a path traversal vulnerability in the display of the product images.
{% endstep %}

{% step %}
### End-goal

Retrieve the content of the `/etc/passwd` file.
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept the request.
* Click on the product (fetch image), forward the request to modify it to JPG.
* Replace the filename parameter with the payload below.
* Send the request and observe a 200 response.
* The response contains the contents of `/etc/passwd`.
{% endstep %}

{% step %}
### Payload

```
../../../etc/passwd
```
{% endstep %}
{% endstepper %}

## Common obstacles to exploiting path traversal vulnerabilities

* Applications that place user input into file paths often implement defenses against path traversal attacks.
* How to bypass these filters:
  * Developers can strip or block directory traversal sequences from the user-supplied filename. You can bypass this by using an absolute path from the filesystem root:
    * `filename=/etc/passwd`
  * This directly references a file without using traversal sequences.

Lab: File path traversal — traversal sequences blocked with absolute path bypass

{% stepper %}
{% step %}
### Vulnerability

The lab contains a path traversal vulnerability in the display of product images. The application blocks traversal sequences but treats the supplied filename as relative to a default working directory.
{% endstep %}

{% step %}
### End-goal

Retrieve the content of the `/etc/passwd` file.
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept the request.
* Click on the product (fetch image), forward the request to modify it to JPG.
* Replace the filename parameter with the payload below.
* Send the request and observe a 200 response.
* The response contains the contents of `/etc/passwd`.
{% endstep %}

{% step %}
### Payload

```
/etc/passwd
```
{% endstep %}
{% endstepper %}

Another common bypass in labs:

* Use nested traversal sequences such as `....//` or `....\/`. These can revert to simple traversal sequences when the inner sequence is stripped.

Lab: File path traversal — traversal sequences stripped non-recursively

{% stepper %}
{% step %}
### Vulnerability

The lab contains a path traversal vulnerability in the display of product images. The application strips path traversal sequences from the user-supplied filename before using it.
{% endstep %}

{% step %}
### End-goal

Retrieve the content of the `/etc/passwd` file.
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept the request.
* Click on the product (fetch image), forward the request to modify it to JPG.
* Replace the filename parameter with the payload below.
* Send the request and observe a 200 response.
* The response contains the contents of `/etc/passwd`.
{% endstep %}

{% step %}
### Payload

```
....//....//....//etc/passwd
```
{% endstep %}
{% endstepper %}

Another common bypass in labs:

* In some contexts (URL path or the filename parameter of a multipart/form-data request), web servers may strip directory traversal sequences before passing input to the application.
* You can bypass this by URL-encoding or double URL-encoding the traversal characters.
  * `../` can be encoded as `%2e%2e%2f` or double-encoded as `%252e%252e%252f`
  * There are various non-standard encodings such as `..%c0%af` or `..%ef%bc%8f`
* Burp Suite Professional's Intruder provides predefined payload lists (Fuzzing-path-traversal) with encoded paths.

Lab: File path traversal — traversal sequences stripped with superfluous URL-decode

{% stepper %}
{% step %}
### Vulnerability

The lab contains a path traversal vulnerability in the display of product images. The application blocks input that contains path traversal sequences and then performs a URL-decode of the input before using it.
{% endstep %}

{% step %}
### End-goal

Retrieve the content of the `/etc/passwd` file.
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept the request.
* Click on the product (fetch image), forward the request to modify it to JPG.
* Replace the filename parameter with the payload below.
* Send the request and observe a 200 response.
* The response contains the contents of `/etc/passwd`.
{% endstep %}

{% step %}
### Payload

```
..%252f..%252f..%252fetc/passwd
```
{% endstep %}
{% endstepper %}

Another common bypass in labs:

* Some applications require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case you can include the base folder followed by a suitable traversal sequence:

```
filename=/var/www/images/../../../etc/passwd
```

Lab: File path traversal — validation of start of path

{% stepper %}
{% step %}
### Vulnerability

The lab contains a path traversal vulnerability in the display of product images. The application transmits the full file path via a request parameter and validates that the supplied path starts with the expected folder.
{% endstep %}

{% step %}
### End-goal

Retrieve the content of the `/etc/passwd` file.
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept the request.
* Click on the product (fetch image), forward the request to modify it to JPG.
* Replace the filename parameter with the payload below.
* Send the request and observe a 200 response.
* The response contains the contents of `/etc/passwd`.
{% endstep %}

{% step %}
### Payload

```
/var/www/images/../../../etc/passwd
```
{% endstep %}
{% endstepper %}

Another common bypass in labs:

* An application may require the user-supplied filename to end with an expected extension such as `.png`. It may be possible to use a null byte to effectively terminate the file path before the required extension:

```
filename=../../../etc/passwd%00.png
```

Lab: File path traversal — validation of file extension with null byte bypass

{% stepper %}
{% step %}
### Vulnerability

The lab contains a path traversal vulnerability in the display of product images. The application validates that the supplied filename ends with the expected file extension.
{% endstep %}

{% step %}
### End-goal

Retrieve the content of the `/etc/passwd` file.
{% endstep %}

{% step %}
### Analysis

* Use Burp Suite to intercept the request.
* Click on the product (fetch image), forward the request to modify it to JPG.
* Replace the filename parameter with the payload below.
* Send the request and observe a 200 response.
* The response contains the contents of `/etc/passwd`.
{% endstep %}

{% step %}
### Payload

```
../../../etc/passwd%00.png
```
{% endstep %}
{% endstepper %}

## How to prevent a path traversal attack

* Avoid passing user-supplied input to filesystem APIs altogether.
* Use two layers of defense to prevent attacks:
  * Validate user input before processing it.
  * Compare user input with a whitelist of permitted content (for example, allow only alphanumeric characters).
* Append the input to the base directory and use a platform filesystem API to canonicalize the path.
* Verify the canonicalized path starts with the expected base directory.

Example Java code to validate the canonical path of a file based on user input:

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
}
```
