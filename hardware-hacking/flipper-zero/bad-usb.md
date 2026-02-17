# Bad USB

On this page you will learn how Bad USB devices work and how to use them in Flipper Zero via USB and via Bluetooth Low Energy (BLE).

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-PUVMYpliqUJ_2-MPHnZtf-20241025-125639.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=12b4122&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Some of the techniques described in this section may be **illegal** if performed without authorization. I am not responsible for the misuse of the techniques described in this manual.

Flipper Zero can act as a [BadUSB device](https://web.archive.org/web/20220816200129/https://github.com/hak5darren/USB-Rubber-Ducky/wiki/) , recognized by computers as a [Human Interface Device](https://en.wikipedia.org/wiki/Human_interface_device) (HID), such as a keyboard. A BadUSB device can change system settings, open backdoors, recover data, initiate reverse shells, or essentially do anything that can be achieved with physical access. This is done by executing a set of commands written in the Rubber Ducky scripting language, also known as DuckyScript. This set of commands is also called a payload.

Insert a microSD card to use the Bad USB app. Before using the Bad USB app, be sure to update the Flipper Zero firmware with a microSD card inserted, as Flipper Zero stores databases on a microSD card. For more information about the update process, visit the [firmware update page.](https://docs.flipperzero.one/basics/firmware-update)﻿﻿

### Flipper Zero programming language <a href="#x8ppp" id="x8ppp"></a>

Before using Flipper Zero as a BadUSB device, you must write a payload in .txt format using any common ASCII text editor that supports the programming language. Flipper Zero can execute the extended Rubber Ducky programming syntax. This syntax is compatible with the classic [Rubber Ducky 1.0 programming](https://web.archive.org/web/20220816200129/http://github.com/hak5darren/USB-Rubber-Ducky/wiki/Duckyscript) language but provides additional commands and functions, such as the ALT+Numpad input method, the SysRq command, and more.

For more information about the Flipper Zero scripting language, see [this page.](https://developer.flipper.net/flipperzero/doxygen/badusb_file_format.html)

A useful resource is Hak5's Payload Studio website, where we can develop our scripts in Duckyscript format and download them locally:



{% embed url="https://payloadstudio.hak5.org/community/" %}

### Loading new payloads into Flipper Zero <a href="#iomsq" id="iomsq"></a>

Once the payload is created, you can load it onto your Flipper Zero via [qFlipper](https://docs.flipperzero.one/qflipper) or [the Flipper Mobile app](https://docs.flipperzero.one/mobile-app) in the folder `SD Card/badusb/`. New payloads you add will be available in the Bad USB app.

﻿Upon uploading, files with the same name will be overwritten without prior notice.﻿﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252F7xRB1w7R2YrD3dpdEKBp%252Fqflipper_file_manager-ezgif.com-video-to-gif-converter.gif%3Falt%3Dmedia%26token%3Ddb1b7d91-fe0d-42a4-9ddf-b0832327f385&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=a04bb0a9&#x26;sv=2" alt=""><figcaption></figcaption></figure>

#### Interesting script repositories <a href="#repositorios-interesantes-de-scripts" id="repositorios-interesantes-de-scripts"></a>

{% embed url="https://github.com/stars/afsh4ck/lists/flipper-zero" %}

### How to use Flipper Zero as a BadUSB device <a href="#uk2m2" id="uk2m2"></a>

#### Via USB connection <a href="#oejsx" id="oejsx"></a>

To convert your Flipper Zero into a BadUSB device using USB, do the following:

1. If qFlipper is running on your computer, close it.﻿
2. On your Flipper Zero, go to **Main Menu -> Bad USB**
3. Select the payload and press the **OK button.**
4. Go to **Settings**
5. _(Optional_ ) If necessary, you can change the keyboard layout (US English is the default).﻿
6. Select connection type: **USB**
7. Connect your Flipper Zero to your computer using a USB cable.
8. Press **Run** to execute the payload on the computer.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252Ftb42uWVsAvtAMcfBO3mu%252Fbad_usb_compressed-ezgif.com-video-to-gif-converter.gif%3Falt%3Dmedia%26token%3D0b4178c4-5b28-44f6-b086-53d1ed95e025&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=57e6e82c&#x26;sv=2" alt=""><figcaption></figcaption></figure>

#### ﻿Through the BLE connection﻿ <a href="#wcjxy" id="wcjxy"></a>

To convert your Flipper Zero into a BadUSB device using BLE, do the following:

1. Activate Bluetooth on your Flipper Zero by going to **Main Menu -> Settings -> Bluetooth**
2. If qFlipper is running on your computer, close it.
3. On your Flipper Zero, go to **Main Menu -> Bad USB**
4. Select the payload
5. Go to **Settings**
6. _(Optional)_ If necessary, you can change the keyboard layout (US English is the default).
7. Select the connection type: **BLE**
8. Press **BACK**
9. On your computer, go to Bluetooth settings and connect to the detected BadUSB wireless device.
10. Confirm the connection both on your computer and on Flipper Zero (by selecting **OK** )
11. On your Flipper Zero, press Run **to** execute the payload on the computer.
