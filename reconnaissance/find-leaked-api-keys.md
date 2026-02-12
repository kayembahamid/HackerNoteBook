# Find Leaked API Keys

Finding API keys which are leaked is crucial work for penetration testing or bug bounty. If we found the API keys leaked, sensitive information is at risk of being stolen. So immediate actions must be taken.

### Awesome Resources <a href="#awesome-resources" id="awesome-resources"></a>

*   [Keyhacks](https://github.com/streaak/keyhacks)

    This repository lists quick ways to find API keys of various providers.

### Using Trufflehog <a href="#using-trufflehog" id="using-trufflehog"></a>

[Trufflehog](https://github.com/trufflesecurity/trufflehog) is a CLI tool to find, verify, and analyze leaked credentials.

```
trufflehog git https://github.com/<username>/<repo> --results=verified,unknown
```

### Google Dorks <a href="#google-dorks" id="google-dorks"></a>

Google Dorks is useful to search leaked API keys/tokens.\
\*Here is the simple example so might be unuseful. Please see Awesome Resources section if you are seriously looking for that.

#### Common APIs <a href="#common-apis" id="common-apis"></a>

Try changing the site domain and the extensions e.g. **`js`, `py`, `go`**.

```shellscript
# GitHub repositories
site:github.com ext:php "api-key"
site:github.com ext:php "api_key"
site:github.com ext:php "api-token"
site:github.com ext:php "api_token"
site:github.com ext:php "access-token"
site:github.com ext:php "access_token"
site:github.com ext:php "x-api-key"
site:github.com ext:php "x_api_key"
site:github.com ext:php "x-api-token"
site:github.com ext:php "x_api_token"
site:github.com ext:php "x-access-token"
site:github.com ext:php "x_access_token"

# GitLab repositories
site:gitlab.com ext:php "api-key"
```

#### AWS <a href="#aws" id="aws"></a>

```shellscript
site:github.com ext:py "ap-northeast-1.amazonaws.com" "x-api-key"
```

#### Google APIs <a href="#google-apis" id="google-apis"></a>

```shellscript
site:github.com ext:py "googleapis.com" "?key="
```

#### Hugging Face <a href="#hugging-face" id="hugging-face"></a>

```shellscript
site:github.com ext:py "https://api-inference.huggingface.co/models" "Authorization: Bearer"
```

#### OpenAI <a href="#openai" id="openai"></a>

```shellscript
site:github.com ext:py "https://api.openai.com/v1/models" "Authorization: Bearer"
```
