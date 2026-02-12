# Steganography

Steganography is the practice of representing information within another message or physical object, in such a manner that the presence of the information is not evident to human inspection.

### Basic Analysis <a href="#basic-analysis" id="basic-analysis"></a>

```shellscript
open example.jpg
file example.jpg

strings example.jpg
# Display the first N lines (default: 10 lines)
strings example.jpg | head
strings example.jpg | head -n 50
# Display the last N lines (default: 10 lines)
strings example.jpg | tail
strings example.jpg | tail -n 50

xxd example.jpg
xxd example.jpg | head

# -e: extract data inside a file
binwalk -e example.jpg

# Read meta information & embedded data
exiftool example.jpg

# GUI Analyzer
# https://github.com/zardus/ctf-tools/blob/master/stegsolve/install
java -jar stegsolve.jar
```

#### Using OSINT <a href="#using-osint" id="using-osint"></a>

Search the image information using search engines.

* [Google Images](https://www.google.com/imghp?hl=EN)

### JPG <a href="#jpg" id="jpg"></a>

```shellscript
# Get hidden data
steghide info sample.jpg
steghide extract -sf sample.jpg

# Crack the passphrase of steghide
stegseek --crack sample.jpg /usr/share/wordlists/rockyou.txt
# --seed: Using default seed as passphrase
stegseek --seed sample.jpg
```

### PNG <a href="#png" id="png"></a>

```shellscript
# PNG & BMP only - https://github.com/zed-0xff/zsteg
zsteg -a sample.png
```

### QR Code Image (JPG/PNG) <a href="#qr-code-image-jpgpng" id="qr-code-image-jpgpng"></a>

```shellscript
zbarimg QR.png
```

If the `zbarimg` command does not exist, install it with the following command:

```shellscript
sudo apt install zbar-tools
```

### PDF <a href="#pdf" id="pdf"></a>

```shellscript
# If the 'pdfinfo' does not exist in your system, install it with 'sudo apt install poppler-utils'
pdfinfo sample.pdf
# with password
pdfinfo -upw 'password' example.pdf

# Convert PDF to text
pdftotext example.pdf example.txt
# with password
pdftotext -upw 'password' example.pdf example.txt
```

#### Crack PDF Password <a href="#crack-pdf-password" id="crack-pdf-password"></a>

```shellscript
 # 1. Convert
pdf2john example.pdf > hash.txt
# or
/usr/share/john/pdf2john.pl example.pdf > hash.txt

# 2. Crack
john --format=pdf --wordlist=wordlist.txt hash.txt
```

### PPM <a href="#ppm" id="ppm"></a>

```
outguess-extract example.ppm out.ppm
```

### npiet <a href="#npiet" id="npiet"></a>

[**npiet**](https://www.bertnase.de/npiet/) is an interpreter for **the piet programming language**.\
It takes as input a portable pixmap (PPM) and PNG, GIF.

1.  **Download and Compile**

    First of all, download the npiet and extract it.

    ```shellscript
    wget https://www.bertnase.de/npiet/npiet-1.3f.tar.gz
    tar -xf npiet-1.3f.tar.gz
    ```

    Then compile the "npiet.c".

    ```shellscript
    cd npiet-1.3f
    gcc npiet.c -o npiet
    ```
2.  **Decode**

    After compiling, decode the image files

    ```shellscript
    ./npiet example.png
    ./npiet example.ppm
    ./npiet example.gif
    ```

### Embed Hidden Data <a href="#embed-hidden-data" id="embed-hidden-data"></a>

#### Exiftool <a href="#exiftool" id="exiftool"></a>

```shellscript
exiftool -Key="value" sample.jpg
```

#### Steghide <a href="#steghide" id="steghide"></a>

```shellscript
steghide embed -ef sample.jpg
```

#### Outguess <a href="#outguess" id="outguess"></a>

**Outguess** is a steganography tool for JPG, PPM and PNM.

```shellscript
outguess -k "passphrase" -d hidden.txt example.jpg out.jpg
```
