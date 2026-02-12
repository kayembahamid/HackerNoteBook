# Spectrogram

A spectrogram is a visual representation of the spectrum of frequencies of a signal as it varies with time.

### Online Tools <a href="#online-tools" id="online-tools"></a>

*   [**Spectrum Analyzer**](https://academo.org/demos/spectrum-analyzer/)

    Display a spectrum of signal amplitudes on different frequencies.\
    Upload audio file like .wav or .mp3, .ogg.
* [**Spectral Analyzer**](https://www.dcode.fr/spectral-analysis)
* [**Morse Code Adaptive Audio Decoder**](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

<br>

### Using Audacity <a href="#using-audacity" id="using-audacity"></a>

Audacity is an audio editor which also can be used for decoding signals in audio files.

1. Open an audio file in Audacity.
2. Click the name of the file at left menu (which contains the reverse triangle icon).
3. In the drop-down menu, check **Spectrogram**.
4. If you want to edit advanced settings, click **Spectrogram Settings** in the menu and edit values.
5. Click **Play** button.

<br>

### Using Inspectrum <a href="#using-inspectrum" id="using-inspectrum"></a>

[Inspectrum](https://github.com/miek/inspectrum) is a radio signal analyzer for **.cf32**, **.cf64**, etc.

<br>

### Using Rtl-433 <a href="#using-rtl-433" id="using-rtl-433"></a>

[rtl-433](https://github.com/merbanan/rtl_433) decodes radio transmissions from devices on the ISM bands.

```
# -A: Pulse analyzer.
rtl_433 -A <file>
```
