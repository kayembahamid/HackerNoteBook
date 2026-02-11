# Password cracking

## Password cracking

### Identify hash

```bash
# https://github.com/noraj/haiti
haiti [hash]
```

### Dictionary creation

```bash
# Pydictor
# https://www.github.com/landgrey/pydictor.git
pydictor.py -extend TERM --leet 0 1 2 11 21 --len 4 20

# Username generator
# https://github.com/benbusby/namebuster
namebuster https://example.com
namebuster "term1, term2"

https://app.wgen.io/

```

#### Examples

```bash
# Numeric dictionary length 4
python3 pydictor.py -base d --len 4 4

# Capital letters dictionary length 4
python3 pydictor.py -base c --len 4 4

# Prepend word + digits 5 length
python3 pydictor.py --len 5 5 --head raj -base d

# Append word after digits 5 length
python3 pydictor.py --len 5 5 --tail raj -base d

# Permute chars in word
python3 pydictor.py -char raj

# Multiple permutations
python3 pydictor.py -chunk abc ABC 666 . _ @ "'"

# Dictionary based in word, added complexity 4 and fixed length
python pydictor.py -extend raj --level 4 --len 1 6

# Interactive mode
python3 pydictor.py --sedb
```

#### Options

```bash
-base dLc # Base digits, Lowercase letters and Capital letters
--encode b64 # Encode output
```

### jtr

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash
```

### Hashcat

#### Wiki

#### Hashes

#### Examples

```bash
# Dictionary
hashcat -m 0 -a 0 hashfile dictionary.txt -O --user -o result.txt

# Dictionary + rules
hashcat -m 0 -w 3 -a 0 hashfile dictionary.txt -O -r haku34K.rule --user -o result.txt

# Mask bruteforce (length 1-8 A-Z a-z 0-9)
hashcat -m 0 -w 3 -a 3 hashfile ?1?1?1?1?1?1?1?1 --increment -1 --user ?l?d?u
hashcat -m 0 -w 3 -a 3 hashfile suffix?1?1?1 -i -1 --user ?l?d

# Modes
-a 0 = Dictionary (also with rules)
-a 3 = Bruteforce with mask 

# Max performance options
--force -O -w 3 --opencl-device-types 1,2

# Output results
-o result.txt

# Ignore usernames in hashfile
--user/--username

# Masks
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a = ?l?u?d?s
?b = 0x00 - 0xff
```

#### Useful hashes

**Linux Hashes - /etc/shadow**

| ID   | Description                   |
| ---- | ----------------------------- |
| 500  | md5crypt $1$, MD5(Unix)       |
| 200  | bcrypt $2\*$, Blowfish(Unix)  |
| 400  | sha256crypt $5$, SHA256(Unix) |
| 1800 | sha512crypt $6$, SHA512(Unix) |

**Windows Hashes**

| ID   | Description |
| ---- | ----------- |
| 3000 | LM          |
| 1000 | NTLM        |

**Common Hashes**

| ID    | Description | Type     |
| ----- | ----------- | -------- |
| 900   | MD4         | Raw Hash |
| 0     | MD5         | Raw Hash |
| 5100  | Half MD5    | Raw Hash |
| 100   | SHA1        | Raw Hash |
| 10800 | SHA-384     | Raw Hash |
| 1400  | SHA-256     | Raw Hash |
| 1700  | SHA-512     | Raw Hash |

**Common Files with password**

| ID    | Description                                     |
| ----- | ----------------------------------------------- |
| 11600 | 7-Zip                                           |
| 12500 | RAR3-hp                                         |
| 13000 | RAR5                                            |
| 13200 | AxCrypt                                         |
| 13300 | AxCrypt in-memory SHA1                          |
| 13600 | WinZip                                          |
| 9700  | MS Office <= 2003 $0/$1, MD5 + RC4              |
| 9710  | MS Office <= 2003 $0/$1, MD5 + RC4, collider #1 |
| 9720  | MS Office <= 2003 $0/$1, MD5 + RC4, collider #2 |
| 9800  | MS Office <= 2003 $3/$4, SHA1 + RC4             |
| 9810  | MS Office <= 2003 $3, SHA1 + RC4, collider #1   |
| 9820  | MS Office <= 2003 $3, SHA1 + RC4, collider #2   |
| 9400  | MS Office 2007                                  |
| 9500  | MS Office 2010                                  |
| 9600  | MS Office 2013                                  |
| 10400 | PDF 1.1 - 1.3 (Acrobat 2 - 4)                   |
| 10410 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1      |
| 10420 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2      |
| 10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8)                   |
| 10600 | PDF 1.7 Level 3 (Acrobat 9)                     |
| 10700 | PDF 1.7 Level 8 (Acrobat 10 - 11)               |
| 16200 | Apple Secure Notes                              |

**Database Hashes**

| ID    | Description                 | Type            | Example Hash                                                                                                                                                     |
| ----- | --------------------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 12    | PostgreSQL                  | Database Server | a6343a68d964ca596d9752250d54bb8a:postgres                                                                                                                        |
| 131   | MSSQL (2000)                | Database Server | 0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578                                                                   |
| 132   | MSSQL (2005)                | Database Server | 0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe                                                                                                           |
| 1731  | MSSQL (2012, 2014)          | Database Server | 0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375                   |
| 200   | MySQL323                    | Database Server | 7196759210defdc0                                                                                                                                                 |
| 300   | MySQL4.1/MySQL5             | Database Server | fcf7c1b8749cf99d88e5f34271d636178fb5d130                                                                                                                         |
| 3100  | Oracle H: Type (Oracle 7+)  | Database Server | 7A963A529D2E3229:3682427524                                                                                                                                      |
| 112   | Oracle S: Type (Oracle 11+) | Database Server | ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130                                                                                                    |
| 12300 | Oracle T: Type (Oracle 12+) | Database Server | 78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225 |
| 8000  | Sybase ASE                  | Database Server | 0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2                                                                           |

**Kerberos Hashes**

| ID    | Type          | Example        |
| ----- | ------------- | -------------- |
| 13100 | Type 23       | $krb5tgs$23$   |
| 19600 | Type 17       | $krb5tgs$17$   |
| 19700 | Type 18       | $krb5tgs$18$   |
| 18200 | ASREP Type 23 | $krb5asrep$23$ |

### Files

```bash
https://github.com/kaonashi-passwords/Kaonashi
https://github.com/NotSoSecure/password_cracking_rules
https://crackstation.net/files/crackstation-human-only.txt.gz
https://crackstation.net/files/crackstation.txt.gz
```

## Single characters

### a-z

```
a
b
c
d
e
f
g
h
i
j
k
l
m
n
o
p
q
r
s
t
u
v
w
x
y
z
```

### A-Z

```
A
B
C
D
E
F
G
H
I
J
K
L
M
N
O
P
Q
R
S
T
U
V
W
X
Y
Z
```

### Special characters

```
!
@
#
$
%
^
&
*
(
)
-
_
=
+
[
]
{
}
\
|
;
'
"
:
,
.
<
>
/
?
`
~
```

## Password Cracking

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

### Headings:

This page was getting to be long, so here are shortcuts to the major sections. I broke these out into separate pages for better organization and searchability.

* [Getting the hashes](https://zweilosec.gitbook.io/hackers-rest/os-agnostic/password-cracking/gathering-the-hashes)
* [Wordlist manipulation](https://zweilosec.gitbook.io/hackers-rest/os-agnostic/password-cracking/wordlist-manipulation)
* [Cracking the Hashes](https://zweilosec.gitbook.io/hackers-rest/os-agnostic/password-cracking/cracking-the-hashes)

Not all methods of discovering passwords involve directly "cracking" hashes. Brute forcing logins and direct recovery programs are also viable solutions.

### Default Credentials

Search using your favorite web search engine for default credentials of the technology that is being used, or try the following compilation lists:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)

### Wordlists

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/carlospolop/hacktricks/tree/95b16dc7eb952272459fc877e4c9d0777d746a16/google/fuzzing/tree/master/dictionaries/README.md)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)

### Password Recovery

Password recovery programs: [https://www.passcape.com/products](https://www.passcape.com/products) (TODO:Test these!)

#### ZIP Password Retrieval (with Known Plaintext)

_Download pkcrack_

[https://www.unix-ag.uni-kl.de/\~conrad/krypto/pkcrack/download1.html](https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack/download1.html)

! Before using, it must be built from source

_Syntax_

```bash
./pkcrack -C $encrypted.zip -c file -P $plaintext.zip -p file
```

### Brute forcing logins <a href="#hydra" id="hydra"></a>

An amazing index of brute-force commands: [https://book.hacktricks.xyz/brute-force](https://book.hacktricks.xyz/brute-force)

#### Hydra

Below are a few scriptable examples to brute force logins of common protocols.

| Command                                                                                                                              | Description                                                |
| ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| `hydra -P $pass_list -v $ip snmp -vV`                                                                                                | SNMP: Brute force                                          |
| `hydra -t 1 -l $user -P $pass_list -vV $ip ftp`                                                                                      | FTP: with known user, using password list                  |
| `hydra -vV -u -L $users_list -P $pass_list -t 1 -u $ip ssh`                                                                          | SSH: using users list, and passwords list                  |
| `hydra -vV -u -L $users_list -p $pass -t 1 -u $ip ssh`                                                                               | SSH: with a known password, and a username list            |
| `hydra -vV $ip -s $port ssh -l $user -P $pass_list`                                                                                  | SSH: with known username on non-standard port              |
| `hydra -vV -l $user -P $pass_list -f $ip pop3`                                                                                       | POP3: Brute Force                                          |
| `hydra -vV -L $users_list -P $pass_list $ip http-get $login_page`                                                                    | HTTP GET: with user list and pass list                     |
| `hydra -vV -t 1 -f -l $user -P $pass_list rdp://$ip`                                                                                 | Windows Remote Desktop: with known username, and pass list |
| `hydra -vV -t 1 -f -l $user -P $pass_list $ip smb`                                                                                   | SMB: brute force with known user, and pass list            |
| `hydra -vV -l $user -P $pass_list $ip http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'` | WordPress: brute force an admin login                      |
| `hydra -vV -L $users_list -p $pass $ip http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'`     | WordPress: enumerate users                                 |
| `wpscan --url $url -U $user -P $pass_list`                                                                                           | Use wpscan to brute force password with known user         |

**Other useful Hydra options**

**`-x min:max:charset` -** Generate passwords from min to max length. Charset can contain `1` for numbers, `a` for lowercase and `A` for uppercase characters. Any other character that is added is put in the list.\
Example: `1:2:a1%.` The generated passwords will be of length 1 to 2 and contain lowercase letters, numbers and/or percent signs and periods/dots.

**`-e nsr` -** Do additional checks. `n` for null password, `s` try login as pass, `r` try the reverse login as pass

#### crackmapexec

[https://mpgn.gitbook.io/crackmapexec/](https://mpgn.gitbook.io/crackmapexec/)

### Resources

* [https://www.unix-ninja.com/p/A\_cheat-sheet\_for\_password\_crackers](https://www.unix-ninja.com/p/A_cheat-sheet_for_password_crackers)
* [https://github.com/frizb/](https://github.com/frizb/)
* [https://guide.offsecnewbie.com/password-cracking](https://guide.offsecnewbie.com/password-cracking)
* [https://www.hackingarticles.in/abusing-kerberos-using-impacket/](https://www.hackingarticles.in/abusing-kerberos-using-impacket/)

