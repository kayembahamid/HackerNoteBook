# SAL Logic Analysis

A SAL file is a capture file in Saleae Logic Analyzer.

### Analysis <a href="#analysis" id="analysis"></a>

[**Saleae's Logic Analyzer**](https://www.saleae.com/) is a tool for hardware analysis.\
Download **Logic 2** and start it.

```
chmod +x ./Logic-x.x.x-master.AppImage
./Logic-x.x.x-master.AppImage
```

In the analyzer, click **"Open a capture"** and select the target file such as **".sal"**.\
Open **"Analyzer"** tab on the right of the windows and click on the **"Async Serial"**.\
The dialog opens, then configure some value e.g. **`Bit Rate`**. And click save button.

After configuration, we can see the data analyzed in the Data section. Click the terminal icon then we can see what data was transmitted.\
To add another Async Serial analyer, click the “+” icon on the right of the Analyzers header.

### Read Code <a href="#read-code" id="read-code"></a>

1. Click **File → Export Data** then select **CSV** in the Export Raw Data popup.
2. Click **Export**.

### Calculate Bit Rate from Intervals <a href="#calculate-bit-rate-from-intervals" id="calculate-bit-rate-from-intervals"></a>

```
Bit rate (bit/s) = 1 second / (interval(microseconds) x 10^(-6)) seconds
```

### References <a href="#references" id="references"></a>

* [Saleae Support](https://support.saleae.com/user-guide/using-logic/using-protocol-analyzers)
