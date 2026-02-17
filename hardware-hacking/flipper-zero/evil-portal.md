# Evil Portal

On this page, you will learn how to perform an Evil Portal attack with Flipper Zero to simulate a valid AP using different login templates to steal service credentials.

### Evil Portal <a href="#mifss" id="mifss"></a>

An evil portal `Evil Portal`is a technique used in ethical hacking to intercept and collect credentials from users connected to Wi-Fi networks. It works by creating a malicious webpage that mimics the captive portal of a public or private network, tricking users into entering sensitive information such as usernames and passwords. Attackers often deploy an evil portal in conjunction with other attack tools, such as deauth, to force users to reconnect through the fake portal, thus facilitating the capture of confidential data.

To perform this technique we will use the following repository, which contains the necessary templates to carry out the attack within the directory `/portals`:



{% embed url="https://github.com/bigbrodude6119/flipper-zero-evil-portal" %}

We need to have the Momentum firmware installed for it to work correctly. Once installed, the option will be `Evil Portal`enabled in:

```
Apps > GPIO > ESP > [ESP32] Evil Portal
```

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FlIjYOqOJaGnPgHuQhGvi%252Fevilp-1.png%3Falt%3Dmedia%26token%3D7f7d7a7f-1b28-4d89-a921-8c823ec3c358&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=c6026e7d&#x26;sv=2" alt=""><figcaption></figcaption></figure>

### Import templates <a href="#importar-plantillas" id="importar-plantillas"></a>

We need to download the repository to our computer and import the HTML templates from the directory `/portals`in the following path:

```
SD Card > apps_data > evil_portal > html
```

### Configure AP name <a href="#configurar-nombre-de-ap" id="configurar-nombre-de-ap"></a>

We can configure the AP name in the option `Set AP name`:

To insert spaces, hold down the middle button on the bottom bar `_`, and to type capital letters, hold down the middle button on a letter.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FOjgGI7j5mSY2xE0op2o8%252Fevilp-4.png%3Falt%3Dmedia%26token%3D905363c1-cacb-4bdd-9e10-46edee7091ef&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=56a80ab&#x26;sv=2" alt=""><figcaption></figcaption></figure>

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252F12PnpfMWp7pzH2rD1bDv%252Fevilp-3.png%3Falt%3Dmedia%26token%3Dea7e67b1-a246-4ade-b4b1-12d230b47e27&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=c7435c51&#x26;sv=2" alt=""><figcaption></figcaption></figure>

We can also download the ap.config.txt file and replace the default index.html file so that it loads automatically every time we start Evil Portal:

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FmFDUl6C4eMjT9rZGtXFS%252Fevilp-2.png%3Falt%3Dmedia%26token%3D1fdf24d1-44b5-44af-b953-79a11da9c7bc&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=6b9037d7&#x26;sv=2" alt=""><figcaption></figcaption></figure>

### Select template <a href="#seleccionar-plantilla" id="seleccionar-plantilla"></a>

The option `Select HTML`will display all the HTML templates we've uploaded. We simply need to select the one we want, for example, the Google template.

### Start Evil Portal <a href="#iniciar-evil-portal" id="iniciar-evil-portal"></a>

Once everything is configured, we simply select the "Start Portal" option, and this generates the malicious access point. When a user enters their credentials, we will receive them instantly in the Flipper. A log file will also be saved.
