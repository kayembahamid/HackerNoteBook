# Writing data on Magic Cards

On this page you will learn about compatible magic cards and how to write the UID and data of an original card to an NFC magic card.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-krTDtVEgklKVffjrKttyY-20241025-092905.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=c6284b46&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Standard NFC cards have unique identification numbers (UIDs) assigned by the manufacturer. These numbers cannot be changed. **NFC Magic** or **rewritable UID** cards are special cards that can change their UIDs. This makes Magic cards more powerful: they can copy the UID and data from an original card. There are [different generations](https://lab401.com/blogs/academy/know-your-magic-cards) of Magic cards.

To use this feature, you must download the [NFC Magic app to your Flipper Zero from ](https://lab.flipper.net/apps/nfc_magic)[Applications.](https://docs.flipper.net/apps)﻿﻿

### Enter card details <a href="#z3dni" id="z3dni"></a>

**Flipper Zero can write data to Gen1** , **Gen2** and **Gen4** magic cards , as well as to **regular MIFARE Classic®** cards (without rewriting the UID).

**Gen1 magic cards** can be configured as the following card type:

* MIFARE Classic® 1K

**Gen2 magic cards** can be configured as the following card type:

* MIFARE Classic® 1K (requires a compatible Gen 2 card)
* MIFARE Classic® 4K (requires a compatible Gen 2 card)

**Gen4 (Ultimate) magic cards** can be configured as the following card types:

* Any MIFARE Classic®
* MIFARE Ultralight® EV1
* MIFARE Ultralight® EV2
* NTAG® 203
* NTAG® 213
* NTAG® 215
* NTAG® 216

To copy the original NFC card, you must write the UID and original data to the NFC magic card by doing the following:

1. ﻿[Read and save the original card](https://docs.flipperzero.one/nfc/read) . Make sure your Flipper Zero reads all sectors or pages of the original card.
2. Go to **Main Menu -> Applications -> NFC -> NFC Magic**
3. Check if you have a compatible Gen1, Gen2, or Gen4 magic card by using the **Check Magic Tag** option and holding the magic card near the back of your Flipper Zero. _Or,_ if you have a password-protected Gen4 card, go to **Gen4 Actions -> Password Authentication** to enter the password manually. Then, use the **Check Magic Tag** option .

Hold the card near the back of your Flipper Zero﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-PYPg8lTp6xekgfufC9sKD-20241107-112912.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=8f996cde&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. If the magic card is compatible, you will see the message below; otherwise, your Flipper Zero will continue trying to determine the card type.

Your Flipper Zero will notify you if you have the magic card

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FTui4uuc2lF8FYPA7hbP-X_image.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=854e5dac&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Go to **More** to see the options for this type of magic card.
2. To write the UID and original card data, use the **Write** option .
3. Select the original card in the browser and keep the magic card near the back of your Flipper Zero.
4. Once your Flipper Zero writes data to the magic card, you will see the message below.

The data from the original card is written onto the magic card

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FFqbYTQSK6M0vIbvjA7rWV_image.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=8878fe53&#x26;sv=2" alt=""><figcaption></figcaption></figure>

You can also format the magic card using the **Erase** option : the UID will be reset to the default value and the data on the sectors or pages will be deleted.
