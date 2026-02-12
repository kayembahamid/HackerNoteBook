# Quadratic Residue

### Basic <a href="#basic" id="basic"></a>

An integer **`x`** is called a quadratic residue modulo **`p`**.

```shellscript
a**2 = x mod p
```

#### Brute Force <a href="#brute-force" id="brute-force"></a>

To calculate a quadratic residue, the following Python script is an example for that.

```shellscript
p = 71

for a in range(p):
    qr = (pow(a, 2, p))
    print(f"a={a} : qr={qr}")
```

#### Legendre Symbol <a href="#legendre-symbol" id="legendre-symbol"></a>

According to Legendre Symbol, the following rules hold:

```shellscript
# `a` is a quadratic residue and `a != 0 mod p`
a**(p-1)/2 mod p == 1

# `a` is a quadratic non-residue mod p
a**(p-1)/2 mod p == -1

# `a ≡ 0 mod p`
a**(p-1)/2 mod p == 0
```

We can check if an integer is a quadratic residue or not referring to the above.

```shellscript
print(pow(a, (p-1)//2, p) == 1)
# If True, `a` is a quadratic resudiue.
```

### References <a href="#references" id="references"></a>

* [CryptoHack](https://cryptohack.org/courses/modular/root1/)
