# Scrypt

Scrypt is a password-based key derivation function.

### Using Scrypt in Python <a href="#using-scrypt-in-python" id="using-scrypt-in-python"></a>

We can use scrypt easily thanks of Pycryptodome.\
We need to install it first.

```
pip install pycryptodome
```

Below is a Python script to derive a key from a password with scrypt.

```
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

password = b'secret'
salt = get_random_bytes(16)
key = scrypt(password, salt, 16, N=2**14, r=8, p=1)
print(f"key: {key.hex()}")
```

### References <a href="#references" id="references"></a>

* [PyCryptdome](https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html#scrypt)
