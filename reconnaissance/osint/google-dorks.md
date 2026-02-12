# Google Dorks

Google Dorks are Google searching techniques.

### Cache/Archive <a href="#cachearchive" id="cachearchive"></a>

Search the latest cached results.

```shellscript
cache:examle.com
```

### Country & Language <a href="#country-language" id="country-language"></a>

If we want to get search results with specific country and language, set parameters `gl` and `hl`.

```shellscript
# gl=us: United States
# hl=en: English
https://www.google.com/search?q=apple&gl=us&hl=en
```

### Directory Listing <a href="#directory-listing" id="directory-listing"></a>

Search websites which allow directory listings. We can retrieve all files if it's enabled in websites.

```shellscript
intext: "Index of /admin"
intext: "Index of /wp-admin"
site:example.com intext: "Index of /admin"
```

### File Types <a href="#file-types" id="file-types"></a>

Specify the filetype e.g. **`pdf`**\`.

```shellscript
filetype:pdf
filetype:pdf "email address"
```

### Sensitive Information <a href="#sensitive-information" id="sensitive-information"></a>

```shellscript
site:github.com "DB_USER"
site:github.com "DB_PASSWORD"

# Filter by datetime
"DB_USER" after:2022-01-01 before:2023-01-01
```

### Subdomains <a href="#subdomains" id="subdomains"></a>

```shellscript
site:*.google.com

# -site: Exclude specific domain
site:*.example.com -site:www.example.com

# Specify file extension
site:*.google.com ext:php
```

### Title <a href="#title" id="title"></a>

Searche keywords contained in page title.

```shellscript
intitle:pentesting
```

### URL <a href="#url" id="url"></a>

Search all URLs containing specific keyword e.g. TLD (com, eu, io, etc.).

```shellscript
inurl:edu
inurl:edu "login"
```

### References <a href="#references" id="references"></a>

* [Exploit DB](https://www.exploit-db.com/google-hacking-database)
