# Signal reading



On this page, you will learn how to read and emulate remote controls, determine the frequency of a remote control, and receive signals on unknown frequencies.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3GUDYkC5JgUWgo6RW8piO-c0M5DM4ySGJfJGLDo4yLo-20241024-180047.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=74235049&#x26;sv=2" alt=""><figcaption></figcaption></figure>

With the Flipper Zero, you can read, save, and emulate different types of remote controls with known protocols.

There are remote controls that operate using protocols that Flipper Zero is not yet familiar with. The signals from these remote controls can be recorded in RAW format, saved, and played back using the [Read RAW](https://docs.flipperzero.one/sub-ghz/read-raw) function .[﻿](https://forum.flipperzero.one/t/my-remote-isnt-supported-how-to-add-new-sub-ghz-protocol-in-flipper-zero/2033)

### Reading procedure <a href="#pl8-x" id="pl8-x"></a>

In read mode, Flipper Zero reads and decodes demodulated signals from remote controls according to known protocols. If the remote control protocol is static, Flipper Zero can save and send the signal.

**Do not use the Read function with your car keys!**

Modern car central locking systems use rotating codes, meaning that each time you use the key fob, it generates a unique code. This code is based on a sequence known to the central locking system and is used to unlock the car. If you capture the key fob's signal and reproduce it in the car, you risk desynchronizing the original key, rendering it unusable.﻿

To read and save your remote control signal, do the following:

1. Go to **Main Menu -> Sub-GHz** .
2. Press **Read** and then press the button on the remote control that you want to read.

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2F3LARdEupzZR64-chUzbPH_monosnap-miro-2023-07-14-12-19-41.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=5ca60d0d&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. When the signal is captured, press **OK** and then press **Save** .

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FoSgQs07b-5ukhIV49qyaX_monosnap-miro-2023-07-12-19-43-57.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=2913ea88&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Name the captured signal and then press **Save** .

﻿Remote controls have different frequencies and modulations. To read the signals correctly, it is necessary to know the remote control's parameters and configure the Flipper Zero accordingly. If the Flipper Zero cannot read the signal with the default settings, you will need to adjust the frequency and modulation parameters in the configuration menu.﻿﻿

### Settings menu <a href="#yjx97" id="yjx97"></a>

In this menu, you can manually change frequencies and hop frequencies, manually change modulations, and lock the keypad while searching for signals. To open the configuration menu, on the scan screen, press **Config** . You will see the following:

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FayaJKt_oZ7ZE8eP619laK_monosnap-miro-2023-07-14-16-27-45.jpg%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=1b761808&#x26;sv=2" alt=""><figcaption></figcaption></figure>

### Frequency setting <a href="#id-1zaxs" id="id-1zaxs"></a>

You can change the frequencies on which Flipper Zero receives signals. In the **settings menu** , by pressing **LEFT** or **RIGHT,** you can manually configure the frequencies from the list:

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fcdn.flipperzero.one%2FMonosnap_Miro_2022-08-23_14-24-29.png&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=530cf85a&#x26;sv=2" alt=""><figcaption></figcaption></figure>

To read the signal correctly, you need to determine the remote control's frequency. You can do this using the Frequency Analyzer function.

### Frequency Analyzer <a href="#bwvdc" id="bwvdc"></a>

During the analysis, Flipper Zero scans the signal strength at all frequencies available in the settings menu. Flipper Zero displays the frequency with the highest Received Signal Strength Indicator (RSSI) value, indicating a signal strength greater than -90 [dBm](https://en.wikipedia.org/wiki/DBm) .

To determine the remote control frequency, do the following:

1. Place the remote control very close to the left side of your Flipper Zero.

﻿It is important to place the remote control very close to your Flipper Zero to avoid intercepting signals from other devices.﻿

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FnR_6aWyXoMwgfH-_fo2Ff_image.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=462c73bc&#x26;sv=2" alt=""><figcaption></figcaption></figure>

1. Go to **Main Menu -> Sub-GHz -> Frequency Analyzer**
2. On your remote control, press and hold the button you want to analyze.
3. Check the measured frequency value on the screen.

Pressing the **LEFT** or **RIGHT** button will take you to the second screen, which displays up to 15 measured frequencies. On the second screen, you can sort the measured frequencies by pressing the **OK** button .

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2Fimages.archbee.com%2F3StCFqarJkJQZV-7N79yY%2FGmsu49H4Ga7x6aWwbLWBO_image.png%3Fformat%3Dwebp&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=7da50daa&#x26;sv=2" alt=""><figcaption></figcaption></figure>

The results of the analysis may be approximate. Flipper Zero displays values ​​that can help you determine the frequency band on which the signal is being sent. In most cases, signals are sent on frequencies in the 315, 433, and 868 MHz bands.﻿﻿

### Jumping between frequencies (Hop) <a href="#otoen" id="otoen"></a>

To receive a signal on an unknown frequency, use hopping mode. In this mode, Flipper Zero rapidly switches between available frequencies and measures the signal strength. Once the signal strength exceeds -90 dBm, the switching stops, and Flipper Zero receives the signal on that frequency for one second; then, the frequency switching resumes.

To search for signals in Hop mode, in the **Settings Menu** , set **Hop** to **ON** .

<figure><img src="https://afsh4ck.gitbook.io/ethical-hacking-cheatsheet/~gitbook/image?url=https%3A%2F%2F2648005400-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FRolFIJKRJaxKzAUqQKJb%252Fuploads%252FvuM3JdMIYAFJgrPIVvED%252Fimage.png%3Falt%3Dmedia%26token%3Dc07e7f0c-bf7b-453c-85c8-d5f7c8549952&#x26;width=768&#x26;dpr=3&#x26;quality=100&#x26;sign=3ad41984&#x26;sv=2" alt=""><figcaption></figcaption></figure>

﻿The change between frequencies takes some time, so signals transmitted at the time of the change may be lost. For better signal reception, set a fixed frequency determined by the frequency analyzer.﻿

In jump mode you can also change the modulations manually.

### Modulation configuration <a href="#znwgy" id="znwgy"></a>

To capture the remote control signal, you must configure the correct modulation settings on your Flipper Zero. Because the Flipper Zero is not a software-defined radio, you must configure the correct modulation before scanning the signal; otherwise, you will not receive the correct data.

Flipper Zero supports [amplitude (AM)](https://en.wikipedia.org/wiki/Amplitude_modulation) and [frequency (FM)](https://en.wikipedia.org/wiki/Frequency_modulation) signal modulation . In the **settings menu** , pressing **LEFT** or **RIGHT** allows you to manually configure the signal modulations from the list.

* **AM270:** amplitude modulation with a bandwidth of 270 kHz.
* **AM650:** Amplitude modulation with a bandwidth of 650 kHz (set as default).
* **FM238:** frequency modulation with a bandwidth of 270 kHz and a [deviation](https://www.youtube.com/watch?v=gFu7-7lUGDg\&t=142s) of 2.380371 kHz.
* **FM476:** frequency modulation with a bandwidth of 270 kHz and a deviation of 47.60742 kHz.

### Bin\_RAW <a href="#xedsv" id="xedsv"></a>

This option allows you to process RAW signals that were not decoded during the reading process. Processing involves removing background noise, eliminating repeated signal segments, and correcting synchronization errors.

To use this feature, you must manually enable the Bin\_RAW option. Additionally, it's important to verify that the frequency and modulation parameters match those of your remote control for optimal functionality.

### Lock keyboard <a href="#vycdi" id="vycdi"></a>

This feature allows you to lock the keypad while your Flipper Zero is scanning for signals. To lock the keypad, in the **Setup Menu** , select **Lock Keypad** and press **OK** .

### Signal transmission (Emulation) <a href="#y7ifn" id="y7ifn"></a>

Flipper Zero can send saved signals that are recorded on frequencies permitted for transmission in your region.

To send a stored signal with Flipper Zero, do the following:

1. Go to **Main Menu -> Sub-GHz -> Saved**
2. Select the signal and then press **Emulate**
3. Press **Send** to send the saved signal

Some frequencies may be blocked for transmission in your region. Flipper Zero can receive signals on all frequencies within the operating bands. However, Flipper Zero can only transmit signals on frequencies permitted for transmission in your region.﻿

For more information on permitted transmission regions and frequencies, visit the [Frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) page .

### Listening to walkie-talkies <a href="#id-9w8q" id="id-9w8q"></a>

It's possible to listen to analog walkie-talkies through the Flipper Zero's speaker. Although not originally intended, this functionality is enabled by the sub-GHz read and RAW data read capabilities.

This feature may not work properly

The Flipper Zero is designed to receive digital signals. When it receives an analog FM modulated radio signal, the device processes it as digital data and interprets frequencies above a certain threshold as 1 and those below as 0. Furthermore, the Flipper Zero's speaker is not designed for reproducing the human voice. To use this function effectively, speak loudly enough into the walkie-talkie.﻿

To start listening to a walkie-talkie:

1. Go to **Main Menu -> Sub-GHz**
2. Select:

* **Read** : for listening only.
* **Read RAW** : for listening and recording.

1. Go to **Settings**
2. Set **the frequency** to the walkie-talkie frequency you wish to listen to.
3. Set **the modulation** to **FM238**
4. Set **the sound** to **ON**
5. (Optional) If you have selected **Read RAW** , you can also configure **the RSSI Threshold** to record only signals that exceed the set signal strength level. [Learn more about configuring the RSSI Threshold.](https://docs.flipper.net/sub-ghz/read-raw#yDGEq)﻿
6. Press **BACK**
7. If you have selected **Read RAW** , press **OK** to start listening.

All set. Now, if the person on the other end speaks loudly enough, you'll be able to hear their voice through the ringtone of your Flipper Zero.
