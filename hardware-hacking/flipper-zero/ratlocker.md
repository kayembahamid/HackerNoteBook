# RatLocker

RatLocker is a simulation of ransomware installation on the computer we connect it to, and a perfect prank to scare our friends.

{% hint style="warning" %}
Although Ratlocker is a joke designed to educate or entertain, it's important to use it ethically and responsibly. Do not use it without the user's explicit consent, as this could be interpreted as malicious behavior.
{% endhint %}

### Ratlocker: "Malware" Simulator (.ratl0ck3r) <a href="#ratlocker-simulador-de-malware-.ratl0ck3r" id="ratlocker-simulador-de-malware-.ratl0ck3r"></a>

Ratlocker is a prank payload created by **ratcode404 (available at ratcode404.github.io** ). This script generates fake "malware" that simulates locking files and setting a wallpaper, but allows for easy recovery without loss of data or important settings.

This tool is located in this repository at / `prank/win/RatLocker`:

{% embed url="https://github.com/FalsePhilosopher/badusb/tree/main" %}

Victim's desktop background

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252F8EUTyV8DRTmoX9edQdCg%252Fimage.png%3Falt%3Dmedia%26token%3Dbbf544c1-66cb-4d33-acb6-d18f7eb9d2ef&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=af536669&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Files "encrypted" with RatLocker

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FSjusAzEuxPPSVkZJPi3s%252Fimage.png%3Falt%3Dmedia%26token%3D793b9ae6-42b3-4526-bf98-7b45c192211e&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=928c9a76&#x26;sv=2" alt=""><figcaption></figcaption></figure>

***

### **Ratlocker Features** <a href="#caracteristicas-del-ratlocker" id="caracteristicas-del-ratlocker"></a>

**1. File Encryption Simulation :**

* Add the extension `.ratl0ck3r`to the files located in `$HOME/Desktop`to simulate encryption.
* The files are not damaged or lose content; recovery is instantaneous upon removal of the extension.

**2. Custom Wallpaper :**

* Change the user's wallpaper without downloading images or using URLs.
* The original image is saved as a backup in the following path:

```shellscript
$HOME/Pictures/wallpaper.ratl0ck3r
```

* This ensures that important records, such as family photos, are not lost.

**3. Fast and "efficient" :**

* The entire process takes less than **7.5 seconds** .
* It can be used to educate or annoy people who leave devices unlocked.

***

### **Requirements** <a href="#requisitos" id="requisitos"></a>

* Operating system: Windows (7/8/8.1/10)
* Device unlocked
* No internet connection required

***

### **Recovery Process** <a href="#proceso-de-recuperacion" id="proceso-de-recuperacion"></a>

Recovering files affected by **Ratlocker** is simple and requires no additional keys or tools.

**1. Remove the Extension`.ratl0ck3r` :**

Each file has an extension `.ratl0ck3r`appended to it. Simply remove this extension to restore the file to its original state.

Example of manual recovery:

* Affected file: `documento.pdf.ratl0ck3r`.
* Rename it to: `documento.pdf`.

**2. Restore Wallpaper :**

The original collection is located at:

```
$HOME/Pictures/wallpaper.ratl0ck3r
```

Change the extension of the saved file (for example, `.ratl0ck3r`to `.jpg`) and set it again as your wallpaper.

**3. Recovery Automation :**

Use the following PowerShell command to quickly restore all files:

```
dir $HOME\Desktop\* | Rename-Item -NewName { $_.name.substring(0,$_.name.length-10) }Este comando elimina la extensión .ratl0ck3r de todos los archivos afectados en el escritorio.
```

**4. Quick Recovery Script :**

The file `rat3ncrypt3er.bat`automatically executes the recovery command and restores the saved wallpaper to `$HOME/Pictures/`its original state.

***

### **Why use Ratlocker** <a href="#por-que-usar-ratlocker" id="por-que-usar-ratlocker"></a>

**1. Total Autonomy :**

It doesn't require an internet connection or rely on external images. All content is generated directly using Windows command-line tools.

**2. Easy Recovery :**

It ensures that all files and settings are restoreable in seconds.

**3. Robustness :**

It has been tested repeatedly without causing errors or accidental losses.

**4. Simplicity and Speed :**

The entire script execution takes less than 7.5 seconds.
