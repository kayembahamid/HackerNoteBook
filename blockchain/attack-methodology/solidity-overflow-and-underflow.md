# Solidity Overflow & Underflow

Solidity is vulnerable to overflow and underflow of uint variables on the version <0.8.

### Overflow <a href="#overflow" id="overflow"></a>

```shellscript
uint8 value = 255;
value++;
// Result: value = 0
```

### Underflow <a href="#underflow" id="underflow"></a>

```shellscript
uint8 value = 0;
value--;
// Result: value = 255
```
