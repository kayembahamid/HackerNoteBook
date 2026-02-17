# Key extraction with MFKey32

On this page you will learn how to perform the MFKey32 attack if you have access to the card and what you can do if you do not.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-LcbRRk6BTxstYEl2WJYmP-20241025-092032.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=75a54161&#x26;sv=2" alt=""><figcaption></figcaption></figure>

If you were unable to read all sectors of the MIFARE Classic® card using the [Read](https://docs.flipperzero.one/nfc/read) function , or if the sectors read were insufficient to gain access, try using the **Extract MF Keys** function . This function performs the MFKey32 attack, which [exploits weaknesses in the ](https://www.cs.bham.ac.uk/~garciaf/publications/Dismantling.Mifare.pdf)[Crypto-1](https://en.wikipedia.org/wiki/Crypto-1) encryption algorithm . MFKey32 is the name of a tool/algorithm used to recover MIFARE Classic keys from the reader's Crypto-1 [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) pairs . It works by recovering the initial state of the Crypto-1 [Linear Feedback Shift Register](https://en.wikipedia.org/wiki/Linear-feedback_shift_register) , which contains the key.

### Sectors on NFC cards <a href="#sectores-en-las-tarjetas-nfc" id="sectores-en-las-tarjetas-nfc"></a>

First, let's understand how the blocks in NFC cards work:

SectorDescriptionKey AKey B

**Sector 0**

It contains the **Manufacturing Block** and the **UID** (Unique Identifier). It cannot be modified on most cards.

Generally `FFFFFFFFFFFF`or`A0A1A2A3A4A5`

Not always accessible

**Sector 1-N**

Data storage space, divided into **16-byte blocks** . Used to store personalized information, such as identifiers, balances, or encrypted data.

It can be customized according to the system.

**Last sector**

It contains the **trailer block** , where keys **A** and **B** are stored , along with the access control bits. It is used to define permissions on the data in the sector.

Key to reading and verifying data

Key to write and modify permissions

* Each **sector** of an NFC MIFARE Classic card typically has **4 blocks** .
* **Key A** is used for authentication and reading in some cases.
* **Key B** may allow writing or configuration of access.
* To read and write in protected sectors, you need to know the **correct keys** .
* Tools like **mfoc** or **mfcuk** can be used to recover keys on some cards.

### If we have access to the card <a href="#lsm_n" id="lsm_n"></a>

The best way to carry out an MFKey32 attack is to gain access to the card, even if not all sectors have been read. By obtaining the reader's key, more sectors of the card can be read, which might be enough to open the door.

To obtain the reader keys and read the MIFARE Classic card, do the following:

1. ﻿[Read and save the card](https://docs.flipperzero.one/nfc/read) with your Flipper Zero.
2. Go to **Main Menu -> NFC -> Saved -> Saved Card Name -> Extract MF Keys.** Flipper Zero will emulate this card for the MFKey32 attack.

Your Flipper Zero is ready to collect the reader's nonces﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FaRTJ3BCig7LCW4CH1YDNL_monosnap-miro-2023-08-03-19-50-38.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=8858bd50&#x26;sv=2" alt=""><figcaption></figcaption></figure>

**Touch the reader** with your Flipper Zero, as shown below. When near the reader, your Flipper Zero will collect the nonces from the reader. Depending on the reader, you may need to touch the reader with your Flipper Zero up to 10 times to simulate several card authentications. On the Flipper Zero screen, the number of collected nonce pairs should increase with each new touch of the reader. If the number of nonce pairs does not increase, the reader is not attempting to authenticate the card emulated by Flipper Zero.

To collect nonces, touch the reader with your Flipper Zero.﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-nh8jrj31z6hOnHThNEcw7-20241107-112652.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=84c88166&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Press **OK** to save the collected nonce pairs to the microSD card. Once the required number of nonce pairs have been collected, the screen will display a " **Finished"** message . After that, you can press the **OK** button to view the captured data, including the sector and key from which they were obtained.

Once the nonces have been collected, you can save them to the microSD card.﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FsR4_86WJB_5haA4HoEwHc_mfkey32noncepairscollected.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=b3123361&#x26;sv=2" alt=""><figcaption></figcaption></figure>

**Retrieve keys** for the collected nonces. You can do this using **the Flipper mobile app.**

1. On your phone, run [the Flipper mobile app](https://docs.flipperzero.one/mobile-app) and sync it with your Flipper Zero
2. Go to **Tools -> Mfkey32 (Detect reader)**

#### **Flipper Lab** <a href="#flipper-lab" id="flipper-lab"></a>

1. Connect your Flipper Zero to your computer using a USB-C cable.
2. On your computer, go to [lab.flipper.net](https://lab.flipper.net/)
3. Go to **NFC tools** and then click the **GIVE ME THE KEYS button**

[![Logo](https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Flab.flipper.net%2Ficons%2Ffavicon-128x128.png\&width=20\&dpr=3\&quality=100\&sign=1c59bb5d\&sv=2)Flipper Lablab.flipper.net](https://lab.flipper.net/)

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252F2NpPu2g7DPUSL01duqRZ%252Fimage.png%3Falt%3Dmedia%26token%3D2c848dca-278b-4a90-bbe2-764d011060b0&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=e8018214&#x26;sv=2" alt=""><figcaption></figcaption></figure>

#### **MFKey Application** <a href="#aplicacion-mfkey" id="aplicacion-mfkey"></a>

To use this feature, you must download the [MFKey application to your Flipper Zero from ](https://lab.flipper.net/apps/mfkey)[Applications.](https://docs.flipper.net/apps)﻿

If you don't have access to a smartphone or computer, you can retrieve the keys for the collected nonces using only your Flipper Zero. Keep in mind that key retrieval takes several minutes due to the device's limited processing power.

1. On your Flipper Zero, go to **Main Menu -> Applications -> NFC**
2. **Run the MFKey** application and press the **OK** button .

The retrieved keys will be displayed on the screen. They can then be added to the **user dictionary** . In some cases, keys cannot be retrieved from the nonces because the reader does not correctly recognize the Flipper Zero emulation.

Once new keys are added to the user dictionary, **reread the card** . The number of keys found and sectors read may increase, indicating that the necessary data was collected.

1. **Emulate the card** and hold your Flipper Zero near the reader for access.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-r7Ac9hzhZeg8dR59XFOv--20241107-112730.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=dc7e3b24&#x26;sv=2" alt=""><figcaption></figcaption></figure>

While emulating the NFC card, hold your Flipper Zero near the reader. If the emulated card does not open the door, try steps 1 through 6 again in case your reader reads multiple sectors sequentially. If, after repeating steps 1 through 6, the number of keys and sectors of the card read by your Flipper Zero does not increase, then the reader and the card are not on the same system or the reader is not vulnerable to the MFKey32 attack.﻿﻿

### If we don't have access to the card <a href="#dsjm" id="dsjm"></a>

Even if you don't have access to the card, you can try to obtain the reader's keys and then add them to the **user dictionary** to expand it.

To obtain and save the reader keys, do the following:

1. Go to **Main Menu -> NFC -> Extract MF Keys** . Flipper Zero will emulate an NFC card for the MFKey32 attack.

Your Flipper Zero is ready to collect the reader's nonces

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FdaUwKKVW4HBirdmwgk7tQ_monosnap-miro-2023-08-03-19-51-29.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=900be4d1&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. **Touch the reader** with your Flipper Zero as shown below.

When you're near the reader, your Flipper Zero will collect the nonces from the reader. Depending on the reader, you may need to tap the reader with your Flipper Zero up to 10 times to simulate several card authentications. On the Flipper Zero screen, the number of collected nonce pairs should increase with each new tap of the reader. If the number of nonce pairs doesn't increase, the reader isn't attempting to authenticate the card being emulated by Flipper Zero.

To collect nonces, touch the reader with your Flipper Zero.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-nGTWC9NTOp_sNkrlmdgce-20241107-112752.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=8292476e&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Press **OK** to save the collected nonce pairs to the microSD card. Once the required number of nonce pairs have been collected, the screen will display a " **Finished"** message . After that, you can press the **OK** button to view the captured data, including the sector and key from which they were obtained.

Once the nonces have been collected, you can save them to the microSD card.﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FEE9Cqc28ze8WOSjyqvNkK_mfkey32noncepairscollected.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=65699d02&#x26;sv=2" alt=""><figcaption></figcaption></figure>

#### **Retrieve keys** from the collected nonces <a href="#recuperar-claves-de-los-nonces-recopilados" id="recuperar-claves-de-los-nonces-recopilados"></a>

You can do it by:

**Flipper mobile app**

1. On your phone, run [the Flipper mobile app](https://docs.flipperzero.one/mobile-app) and sync it with your Flipper Zero
2. Go to **Tools -> Mfkey32 (Detect reader)**

**Flipper Lab**

1. Connect your Flipper Zero to your computer using a USB-C cable.
2. On your computer, go to [lab.flipper.net](https://lab.flipper.net/)
3. Go to **NFC tools** and then click the **GIVE ME THE KEYS button**

**MFKey Application**

To use this feature, you must download the [MFKey application to your Flipper Zero from ](https://lab.flipper.net/apps/mfkey)[Applications.](https://docs.flipper.net/apps)﻿

If you don't have access to a smartphone or computer, you can retrieve the keys for the collected nonces using only your Flipper Zero. Keep in mind that key retrieval takes several minutes due to the device's limited processing power.

1. On your Flipper Zero, go to **Main Menu -> Applications -> NFC**
2. **Run the MFKey** application and press the **OK** button .

The retrieved keys and sector numbers will be displayed on the screen. They can then be added to the **user dictionary** . In some cases, keys cannot be retrieved from the nonces because the reader does not correctly recognize Flipper Zero emulation.
