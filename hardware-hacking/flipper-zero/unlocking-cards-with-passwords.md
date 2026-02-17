# Unlocking cards with passwords

On this page you will learn how to capture the password sent by the reader, generate passwords for compatible card types, and unlock cards by manually entering passwords.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-MFsPWijVuiBwTA2sNqlul-20241107-112823.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=238f15ac&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Some NFC cards have their data organized into pages, such as MIFARE Ultralight® and NTAG® cards. If you cannot read all the pages of the NFC card using the [Read](https://docs.flipperzero.one/nfc/read) function , the card may be password-protected. To unlock the protected card, you can enter the password manually, generate a password to unlock the pages, or retrieve the password from the reader.

Using these features could block your card. Some cards have a security feature that blocks the card after several authentications with an incorrect password.﻿

### Extract the reader's password <a href="#id-2chnn" id="id-2chnn"></a>

If you have access to the reader and the card, try extracting the reader's password by emulating the data on the captured card. The reader can authenticate the card with a password, which can be captured and saved by your Flipper Zero. After that, you can read the data on the remaining pages of the card.

To retrieve the password and unlock the card, do the following:

1. ﻿[Read and keep](https://docs.flipperzero.one/nfc/read) the card
2. Go to **Main Menu -> NFC -> Saved -> Card Name -> Unlock**
3. Select **Unlock with Reader** and then touch the reader with your Flipper Zero.

To capture the password, touch the reader with your Flipper Zero﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-nGTWC9NTOp_sNkrlmdgce-20241107-112752.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=8292476e&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Once you have captured the password, press **Continue**

The captured password is displayed on the screen.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FrWzAZTDZa-jy6y5TsRHl7_flipperzerounlocknfccardswithreader.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=e1e6683c&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Read the card by holding it near the back of your Flipper Zero

Hold the card in the center of the back of your Flipper Zero.﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-PYPg8lTp6xekgfufC9sKD-20241107-112912.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=8f996cde&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Once the pages are unlocked, press **Save.**

The number of pages read is displayed on the screen.﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FnnLEnF_-6NW9uYSM9n6uS_successfulunlockofallpagesofnfccard.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=1038f40c&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Name the card and then press **Save.**

#### If the unlock failed <a href="#dylqr" id="dylqr"></a>

* The card may be connected to another reader.

### Generating the password <a href="#gh6u3" id="gh6u3"></a>

With Flipper Zero, you can generate a password for the NFC technology of amiibo devices and the Xiaomi air purifier. When the card is nearby, Flipper Zero generates the password from the card's UID.

To generate the password and unlock the card, do the following:

1. Go to **Main Menu -> NFC -> Additional Actions -> Unlock NTAG/Ultralight**
2. Select the card type and then hold the card near the back of your Flipper Zero.
3. Once the pages are unlocked, press **Save.**
4. Name the card and then press **Save.**

### Enter the password manually <a href="#id-6i8bg" id="id-6i8bg"></a>

If you know the password, you can enter it manually and unlock the card by doing the following:

1. ﻿[Read and keep](https://docs.flipperzero.one/nfc/read) the card.
2. Go to **Main Menu -> NFC -> Saved** .
3. Select the saved card.
4. Then go to **Unlock with password -> Enter password manually** .
5. Enter the password in hexadecimal and then press **Save** .
6. To unlock the card with the entered password, hold the card near the back of your Flipper Zero.
7. Once the pages are unlocked, press **Save** .
8. Name the card and then press **Save** .
