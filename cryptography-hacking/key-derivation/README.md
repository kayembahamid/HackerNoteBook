# Key Derivation

## Bcrypt <a href="#bcrypt" id="bcrypt"></a>

Bcrypt is a password-hashing function based on the Blowfish cipher.

### Using Bcrypt in Python <a href="#using-bcrypt-in-python" id="using-bcrypt-in-python"></a>

Reference: [https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html#bcrypt](https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html#bcrypt)

To create a bcrypt hash,

```
from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt

password = b"secret"
b64pwd = b64encode(SHA256.new(password).digest())
bcrypt_hash = bcrypt(b64pwd, 12)
print(f"hash: {bcrypt_hash}")
```

To check them,

```
from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt, bcrypt_check, _bcrypt_hash

password = b"secret"
# Specify the hash generated
bcrypt_hash = b"$2a$12$F86jMkaNbEm8lPm6q6zbCuiIGOAsz4azBZkAeSalFYXjctIjiQG1C"

try:
    b64pwd = b64encode(SHA256.new(password).digest())
    bcrypt_check(b64pwd, bcrypt_hash)
    print("Password is correct")
except ValueError:
    print("Incorrect password")
```

### References <a href="#references" id="references"></a>

* [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html#bcrypt)
