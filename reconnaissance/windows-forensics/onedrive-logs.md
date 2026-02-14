# OneDrive Logs

OneDrive log files can be read by deobfuscating.

### Deobfuscating Log Files <a href="#deobfuscating-log-files" id="deobfuscating-log-files"></a>

To read OneDrive logs, we need to deobfuscate log files (**`.odl`, `.odlsent`, `.odlgz`**).\
These logs are located in the following on **Windows**:

* `C:\Users\<username>\AppData\Local\Microsoft\OneDrive\logs\Personal\`
* `C:\Users\<username>\AppData\Local\Microsoft\OneDrive\logs\Business1\`

[This repository](https://github.com/ydkhatri/OneDrive) is useful to deobfuscate OneDrive logs.

```
python -m venv venv
# on Windows
.\venv\Scripts\activate
pip install construct pycryptodome
python odl.py -o .\output.csv c:\Users\\AppData\Local\Microsoft\OneDrive\logs\Personal\
```

After that, we can read the output file (`output.csv`) with tools such as VS Code and Excel.\
This file contains sensitive information such as OneDrive account email, access token, etc.
