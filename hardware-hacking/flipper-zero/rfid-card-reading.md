# RFID card reading

On this page, you will learn how to read, save, and emulate 125 kHz RFID cards with your Flipper Zero.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-N5Zy447XyN9b94MuBkft2-20241024-181130.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=1b65f7ef&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Flipper Zero allows you to read, save, and emulate 125 kHz RFID cards. A 125 kHz RFID card is a [transponder](https://en.wikipedia.org/wiki/Transponder) that stores a unique identification number. When scanned with a reader, a 125 kHz card transmits its identification number. If the card has a compatible protocol, Flipper Zero can read and save the identification number.﻿

Examples of these cards would be a wristband to access a gym, a card to open a hotel room, or a dog chip.

### Supported protocols <a href="#vkado" id="vkado"></a>

Flipper Zero can read 125 kHz RFID cards using the following protocols:

**EM-Micro EM4100**

125 kHz protocol widely used in basic access control applications.

**EM-Micro EM4100/32**

Variant of the EM4100 with a 32-bit format, compatible with low frequency systems (125 kHz).

**EM-Micro EM4100/16**

A variant of the EM4100 with a 16-bit format, used in simple access control systems.

**HID H10301**

26-bit standard used by HID Global for access control in commercial environments.

**IDTECK Idteck**

26-bit protocol used by IDTECK systems for access control and authentication.

**Motorola Indala 26**

125 kHz technology that uses a 26-bit format for corporate access control.

**Kantech IoProx XSF**

Kantech's exclusive protocol for its access control systems with added security.

**AWID**

125 kHz technology used in access control, parking systems, and business applications.

**FECAVA FDX-A**

134.2 kHz identification protocol used primarily in animal identification systems.

**ISO FDX-B**

International standard of 134.2 kHz for animal identification, regulated by ISO 11784/85.

**Generic HID Prox**

125 kHz technology used in multiple generic access control systems.

**Generic HID Ext**

Extended variant of HID Prox with greater data capacity and compatibility with advanced systems.

**Farpointe Pyramid**

Low frequency RFID technology (125 kHz) used in access control systems.

**Viking**

RFID protocol used in Viking-specific security and access control systems.

**Jablotron**

Exclusive protocol used in security and alarm systems manufactured by Jablotron.

**Paradox**

Paradox's own technology for integration with its access control and security systems.

**PAC Stanley**

125 kHz RFID protocol developed for high security access systems.

**Keri**

RFID protocol used in access control systems of the Keri Systems brand.

**Gallagher**

Advanced technology used in physical security and access control solutions.

**Honeywell Nexwatch**

Protocol used in Honeywell security and access control systems.

**Electra**

Protocol used in access and control solutions for residential and commercial applications.

**Securakey**

RFID technology used in access control systems, with low and high frequency options.

### How to read 125 kHz cards <a href="#n6-dm" id="n6-dm"></a>

To read and save data from the 125 kHz card, do the following:

1. Go to **Main Menu -> RFID 125 kHz** .
2. Press **Read** , then hold the card near the back of your Flipper Zero.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-ZSvJK21YCuGtFAnFsyf5x-20241024-181249.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=dcdd0e06&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Do not move the card while reading. The reading process may take several seconds because Flipper Zero changes the encodings every 3 seconds and attempts to match the card's protocol to the list of supported protocols.﻿

During reading, Flipper Zero switches between ASK and PSK encodings every three seconds to read data from the 125 kHz RFID card.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FvmurU-epvnvogwFJ7nv9u_monosnap-miro-2023-09-12-14-53-25.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=dc9b6f09&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Once the reading is complete, review the card data displayed on the screen.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2F1PesPJ3jO3z7DsVZS-Tyl_monosnap-miro-2023-09-12-14-54-23.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=1257fabc&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. To save the card, go to **More -> Save** .
2. Name the card and then press **Save** .

#### If the reading failed <a href="#id-6iwpi" id="id-6iwpi"></a>

* The card may use NFC technology -> Read the card with the [NFC application](https://docs.flipperzero.one/nfc) .
* Flipper Zero changes encoding every three seconds. Some cards may not be read because it can take up to 10 seconds to read the data. -> [Reads the card with the preselected ASK or PSK encoding](https://docs.flipperzero.one/rfid/read#A28I4) .

#### Reading with a preselected encoding <a href="#a28i4" id="a28i4"></a>

Flipper Zero allows reading 125 kHz RFID cards with pre-selected ASK or PSK encoding.

To read and save data from the 125 kHz card with a preselected encoding, do the following:

1. Go to **Main Menu -> RFID 125 kHz -> Additional Actions** .
2. Select **Read ASK** or **Read PSK** .
3. Hold the card near the back of your Flipper Zero.
4. After reading, go to **More -> Save** .
5. Name the card and then press **Save** .

### 125 kHz RFID card emulation <a href="#id-5mrws" id="id-5mrws"></a>

Flipper Zero can emulate stored 125 kHz RFID cards by doing the following:

1. Go to **Main Menu -> RFID 125 kHz -> Saved** .
2. Select the card you want to emulate and then press **Emulate** .

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FrHlSYiV_1dnfnfuP1A-Tc_monosnap-miro-2023-09-12-14-49-16.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=bb6e6777&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Hold your Flipper Zero close to the reader, with the back of the device facing the reader.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-WifMsOzPepWbdVsq7O4u0-20241107-102717.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=9b41b6f6&#x26;sv=2" alt=""><figcaption></figcaption></figure>

## Add RFID cards manually

On this page you will learn how to add a new card and edit a saved or added card.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-4U-OBrJRrXL8KRtJBLVox-20241024-181344.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=e00a598e&#x26;sv=2" alt=""><figcaption></figcaption></figure>

You can store new cards in your Flipper Zero without having to read a physical card. All you have to do is select a protocol and manually enter the card data. The added card can be emulated or [written](https://docs.flipper.net/rfid/write-data) to a blank T5577 card.

### ﻿125 kHz RFID card generation <a href="#generacion-de-tarjetas-rfid-de-125-khz" id="generacion-de-tarjetas-rfid-de-125-khz"></a>

To generate a virtual card, do the following:

1. Go to **Main Menu -> RFID 125 kHz -> Add manually**
2. Select the protocol you wish to use and press **OK.**
3. Enter the card details in hexadecimal and then press **Save**
4. Manually enter the card details﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FyJJLP_jQpK-RioqlVasq7_monosnap-miro-2023-09-12-11-34-22.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=276e4315&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Name the card and then press **Save.**

### 125 kHz RFID card edition <a href="#id-1ocwb" id="id-1ocwb"></a>

You can also edit saved and manually added card data by following these steps:

1. Go to **Main Menu -> RFID 125 kHz -> Saved**
2. Select the saved card you want to edit by pressing **OK** , and then press **Edit.**
3. Enter the new data in hexadecimal and then press **Save**
4. Enter the new card name and then press **Save**

## Writing data to T5577 cards

On this page, you will learn how to write data to T5577 blank cards and what to do if the procedure fails.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-vaj3FU3Tik1TnrSpSj_CW-20241107-102744.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=5f503792&#x26;sv=2" alt=""><figcaption></figcaption></figure>

In general, 125 kHz RFID cards and key fobs are read-only. If they are writable, they typically have a password and use a chip incompatible with Flipper Zero for writing. However, blank rewritable T5577 cards exist, which can be programmed to emulate cards with various low-frequency RFID protocols.

You can write manually saved and added 125 kHz RFID cards to T5577 blank cards. These blank cards come in various shapes and sizes, such as cards, key fobs, stickers, and pet microchips. The Flipper Zero can write data using all supported low-frequency RFID protocols.

### Data writing <a href="#escritura-de-datos" id="escritura-de-datos"></a>

To write data to the card, do the following:

1. Go to **Main Menu -> RFID 125 kHz -> Saved**
2. Select the card you want to write on, and then press **Write.**
3. Hold the Flipper Zero near the blank T5577 card, with the back of the device facing the card.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2F4OLd8i7ScKnLYB400y-H6_image.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=5b9115aa&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Hold the card in the center of the back of your Flipper Zero.4

After writing data to the blank card, the device will display the message **"Written successfully** ".

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2F-ABqxxpZ1edTUlR99IkcE_monosnap-miro-2023-09-12-14-32-23.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=2b7b8251&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Please note that your Flipper Zero may display the message **"Written successfully"** when writing to a read-only card. This can happen if the same data is already present on the read-only card.

### If the writing failed <a href="#id-16d-t" id="id-16d-t"></a>

* The T5577 blank card can be protected with a password.
* You are trying to write to a read-only RFID card, not a blank T5577 card.
* Not all cards are rewritable.﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FpxrZdGMjevNVBwStiQFLK_monosnap-miro-2023-09-12-11-34-39.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=a718be33&#x26;sv=2" alt=""><figcaption></figcaption></figure>
