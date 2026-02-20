# information disclosure vulnerabilities

## Information disclosure

Information disclosure (information leakage) occurs when a website unintentionally reveals sensitive information to its users. This can include:

* Data about other users (usernames, financial information)
* Sensitive commercial or business data
* Technical details about the website and its infrastructure

Why this matters:

* It can reduce testing efficiency and help an attacker find additional/high-severity bugs.
* It can provide the missing pieces when constructing complex, high-severity attacks.

## Examples of information disclosure

* Revealing names of hidden directories, their structure and contents via a `robots.txt`
* Providing access to secure code files via temporary backups
* Mentioning database tables or column names in error messages
* Exposing sensitive information such as credit card details
* Hard-coding API keys, IP addresses, database credentials, and source code
* Hinting at the existence or absence of resources or usernames via subtle differences in application behavior

## How do information disclosure vulnerabilities arise?

* Failure to remove internal content from public content
  * Developer comments in markup sometimes remain visible in production
* Insecure configuration of the website and related technologies
  * Debugging/diagnostic features left enabled
  * Default configurations left unchanged
  * Overly verbose error messages
* Flawed design and behavior of the application
  * Distinct responses for different error states enable enumeration of sensitive data (e.g., valid user credentials)

## Impact of information disclosure

* Direct impact
  * Revealing technical information: directory structure, third-party frameworks, versions
* Indirect impact
  * Exposure of sensitive user data such as credit card details or credentials

## Assessing severity

* Severity depends on how an attacker can practically use the disclosed information.
  * Example: If the site uses an outdated framework version with a known exploit, an attacker can combine the version disclosure with the exploit to gain full compromise.

## How to prevent information disclosure

{% hint style="info" %}
It is difficult to eliminate every possible disclosure because there are many ways information can leak. Focus on reducing exposure and educating teams.
{% endhint %}

Recommended practices:

* Label what information is sensitive and inform the entire production team.
* Audit code for potential information disclosure before deployment.
* Use generic error messages where possible (avoid cues in responses).
* Ensure debugging and diagnostic features are disabled in production.
* Review and understand configuration settings for all components (web server, application frameworks, third-party components).

## Exploiting information disclosure (testing guidance)

* Avoid tunnel vision: do not focus only on one vulnerability type.
* Sensitive data can appear in many places; testing for other issues often uncovers disclosures.
* High-level techniques and tools:
  * Fuzzing
  * Using Burp Suite Scanner and engagement tools
  * Automation (Intruder, wordlists)
  * Logger++ extension
  * Search and grep rules to find keywords in responses
  * Engineering informative responses by studying changes in error messages and behavior

### Fuzzing

* Identify interesting parameters and send crafted strings to reveal unexpected data.
* Observe application behavior (errors may not be visible; time-based differences can indicate issues).

### Automation (Burp Intruder)

* Add payload positions and use pre-built wordlists to test many inputs.
* Compare HTTP status codes, response times, and response lengths to find differences.
* Use grep match/extraction rules to find keywords like `error`, `invalid`, `select`, `sql`, etc.

### Logger++

* Burp extension for logging requests and responses from all Burp tools.
* Allows advanced filters and highlighting to find interesting entries and leaked sensitive data.

### Burp Scanner (Professional)

* Live scanning while browsing and scheduled automated scans.
* Can detect private keys, email addresses, credit card numbers, backup files, directory listings, etc.

### Burp Engagement Tools

* Access from context menu on any HTTP message, proxy entry, or site map item → `Engagement tools`.
* Useful for targeted discovery tasks like searching, finding comments, and discovering content.

### Search and Find Comments

* Advanced search options (regex, negative search) help locate occurrences or absences of specific keywords.
* “Find Comments” locates developer comments and links back to the HTTP request/response.

### Discover content

* Identify additional content and functionality that is not linked from visible site content (additional directories/files).

### Engineering informative responses

* Verbose error messages can disclose interesting information.
* By studying how error messages change with different inputs, you can sometimes extract arbitrary data.

## Common sources of information disclosure

### Files for web crawlers

* Files such as `/robots.txt` and `/sitemap.xml` often list directories to skip and may inadvertently reveal hidden paths.
* These files can appear in the site map during testing.

### Directory listings

* Web servers may be configured to list directory contents automatically.
* Directory listings expose files (temporary files, crash dumps) not intended for public access.

### Developer comments

* Inline HTML comments added during development are sometimes left in production.
* Comments can hint at hidden directories or application logic and are discoverable via Burp or browser dev tools.

### Error messages

* Verbose errors are a common disclosure source.
* Errors can reveal expected input types, exploitable parameters, technology stack names/versions (template engine, database, server).
* Use disclosed version/technology info to search for documented exploits or misconfigurations.

### Debugging data

* May include session variables, hostnames, credentials, file/directory names, encryption keys, or other sensitive info.
* Debugging output might be logged in separate files.

### User account pages

* Profile/account pages often contain emails, phone numbers, API keys.
* Logic flaws (e.g., insecure direct object references) can allow viewing other users’ data:
  * Example: `GET /user/personal-info?user=carlos` (IDOR)

### Source code disclosure via backup files

* Source code provides full context for attacks and may contain hard-coded secrets (API keys, DB credentials).
* Text editors create temporary backup files (e.g., `file~`, `file.bak`) that may expose code when requested directly.
* The server might execute files (e.g., `.php`) rather than returning the source; backup extensions can reveal source content.

### Insecure configuration

* Misconfiguration of third-party components or server features can disclose information.
* Example: HTTP `TRACE` echoes the exact request, potentially exposing internal authentication headers.

### Version control history

* Exposed `.git` directory allows downloading a site’s version control data.
* The repo history can contain committed secrets, diffs showing removed secrets, or other useful snippets.

## Labs (step-by-step)

Use the steppers below to represent the sequential lab exercises described.

{% stepper %}
{% step %}
### Lab: Information disclosure in error messages

#### Vulnerability

Verbose error messages reveal a vulnerable third-party framework version.

#### End-goal

Obtain and submit the framework version number.

#### Analysis / Steps

* In Burp, open product pages and observe `GET` requests with a `productID` parameter.
* Send the `GET /product?productID=1` request to Repeater.
* Change `productID` to a non-integer value to trigger an error, e.g.:
  * `GET /product?productId="example"`
* Inspect the response: a full stack trace is displayed with the framework version (e.g., `Apache Struts 2 2.3.31`).

#### Payload

Send a string where an integer is expected (cause a type error).
{% endstep %}

{% step %}
### Lab: Information disclosure on debug page

#### Vulnerability

A debug page discloses sensitive application information.

#### End-goal

Obtain and submit the `SECRET_KEY` environment variable.

#### Analysis / Steps

* Intercept the home page and inspect source; find an HTML comment linking to `Debug`.
* The comment points to `/cgi-bin/phpinfo.php`.
* Request `/cgi-bin/phpinfo.php` (send to Repeater) and retrieve the page.
* Search response for `SECRET_KEY` environment variable and submit it.

#### Payload

Use browser interception or Burp engagement tools to find comments and follow the linked debug page.
{% endstep %}

{% step %}
### Lab: Source code disclosure via backup files

#### Vulnerability

Source code is leaked via backup files in a hidden directory.

#### End-goal

Obtain and submit the hard-coded database password from the leaked source.

#### Analysis / Steps

* Browse `/robots.txt` and find a `/backup` entry.
* Browse to `/backup` and access `productTemplate.java.bak`.
* Inspect the source code for the connection builder and find the hard-coded Postgres password.
* Submit the password.

#### Payload

Alternatively use Burp → Site map → Engagement tools → Discover content → `/backup` to find the file.
{% endstep %}

{% step %}
### Lab: Authentication bypass via information disclosure

#### Vulnerability

Admin interface has an authentication bypass relying on a custom header.

#### End-goal

Obtain the header name, use it to bypass authentication, access admin interface, and delete user `carlos`.

* Admin credentials example: `wiener:peter`

#### Analysis / Steps

* Request `GET /admin` via Repeater; response mentions admin panel is accessible if logged in as admin or requested from a local IP.
* Send a `TRACE` request and observe the response contains `X-Custom-IP-Authorization` header with your IP.
* Use Burp Proxy → Options → Match and Replace to add the header to all requests:
  * Replace field: `X-Custom-IP-Authorization: 127.0.0.1`
* Browse the site; you should gain admin access and be able to delete `carlos`.

#### Payload

Add `X-Custom-IP-Authorization: 127.0.0.1` header to emulate localhost requests.
{% endstep %}

{% step %}
### Lab: Information disclosure in version control history

#### Vulnerability

Sensitive information is exposed via accessible `.git` data.

#### End-goal

Obtain the administrator password from version control history, log in, and delete user `carlos`.

#### Analysis / Steps

* Browse to `/.git` and download the GIT data:
  * `wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/`
* Open the downloaded repo with a local Git tool.
* Find a commit message like `Remove admin password from config` and inspect the diff for `admin.conf`.
* Locate the leaked admin password (committed earlier) and log in as administrator to delete `carlos`.

#### Payload

Use standard Git tools (or GUI clients) to inspect commit diffs and recover leaked secrets.
{% endstep %}
{% endstepper %}

## Additional labs and examples

(These labs were already covered above but are summarized here for quick reference.)

* Source code backup files: look in `/robots.txt` or use content discovery; inspect `.bak`, `~`, `.old` extensions.
* Debug pages: search for phpinfo, debug, or developer pages linked from comments.
* Version control: check for exposed `.git` or `.svn` directories.
* TRACE/HTTP methods: test for enabled diagnostic methods that leak request content.

## Summary — detection checklist

* Inspect `/robots.txt` and `/sitemap.xml` for hidden paths.
* Crawl and review site map for unusual files and directories (backup files, `.git`, admin tools).
* Search responses for developer comments and verbose errors.
* Test behavior differences (response codes, lengths, timing) to find subtle disclosures.
* Check server configuration for directory listing, TRACE, and other diagnostic methods.
* Use automation and grep/extraction rules to find keywords and secrets in responses.
* Ensure production environments have debugging/diagnostic features disabled and use generic error messages.

## References / Tools

* Burp Suite (Proxy, Repeater, Intruder, Scanner, Engagement tools)
* Logger++ (Burp extension)
* Wordlists for fuzzing
* Git tools for analyzing downloaded `.git` directories

If you want, I can:

* Convert any of the lab steppers into separate GitBook pages.
* Create ready-to-paste Burp match-and-replace snippets or example grep rules for detecting common disclosures.
