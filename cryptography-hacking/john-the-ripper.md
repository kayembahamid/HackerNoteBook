# John the Ripper

John the Ripper is a password cracking tool.

### Basics <a href="#basics" id="basics"></a>

```shellscript
john --format=raw-md5 --wordlist=wordlist.txt hash.txt
```

To search the type of hash, we can add **"--list=format"** option.

```shellscript
john --list=formats
john --list=formats | grep -i sha
john --list=formats | grep -i md5
```

### Filter the Word Length of Wordlists <a href="#filter-the-word-length-of-wordlists" id="filter-the-word-length-of-wordlists"></a>

```shellscript
# Up to 5 characters (-max-len:5)
john --wordlist=/usr/share/wordlists/rockyou.txt -max-len:5 hash.txt

# 4 characters only (-min-len:4 -max-len:4)
john --wordlist=/usr/share/wordlists/rockyou.txt -min-len:4 -max-len:4 hash.txt
```

### Generate Custom Wordlist from Original One <a href="#generate-custom-wordlist-from-original-one" id="generate-custom-wordlist-from-original-one"></a>

#### Command Options <a href="#command-options" id="command-options"></a>

```shellscript
# Min length: 12
# Max length: 14
john --wordlist=./words.txt --min-len:12 --max-len:14 --stdout > new_words.txt

# Make uppercase to lowercase
cat new_words.txt | tr [:upper:] [:lower:] > new_words_lowercase.txt
# Make lowercase to uppercase
cat new_words.txt | tr [:lower:] [:upper:] > new_words_uppercase.txt
```

#### Custom Rules <a href="#custom-rules" id="custom-rules"></a>

Add custom rules to "/etc/john/john.conf"

```shellscript
[List.Rules:Custom]
Az"[0-9][0-9][!?#$%&/()=]"                                                                      "
```

Generate

```shellscript
john --wordlist=./original-wordlist.txt --rules:Custom --stdout > new-wordlist.txt
```

### Remove Cache (Crack Again) <a href="#remove-cache-crack-again" id="remove-cache-crack-again"></a>

If we can crack the hash that was cracked before, remove **"john.pot"** which stores cracked passwords.

```shellscript
rm ~/.john/john.pot
```
