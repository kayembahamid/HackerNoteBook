# Exponentiation

Exponentiation

### Basic <a href="#basic" id="basic"></a>

We can calculate the exponentiation using **'\*\*'** operator in Python.

```shellscript
2 ** 4
# 16

6 ** 8
# 1679616
```

### Using Pow Method in Python <a href="#using-pow-method-in-python" id="using-pow-method-in-python"></a>

The **`pow`** method can be used for the exponentiation.

```shellscript
pow(2, 4)
# 2 ** 4 = 16
```

#### Modular Exponentiation <a href="#modular-exponentiation" id="modular-exponentiation"></a>

In addition, we can find the remainder of dividing a rased value by a specific number.\
This may be sometimes used to find the secret key in **key derivation functions**, etc.

```shellscript
pow(2, 4, 6)
# 2 ** 4 % 6 = 4
```

### Inverse <a href="#inverse" id="inverse"></a>

```shellscript
from Crypto.Util.number import inverse

inverse(3, 10) # 7
pow(3, -1, 10) # 7
```
