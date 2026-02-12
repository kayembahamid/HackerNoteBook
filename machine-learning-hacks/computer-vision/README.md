# Computer Vision

## Image Analysis for Machine Learning <a href="#image-analysis-for-machine-learning" id="image-analysis-for-machine-learning"></a>

Investigate images to get sensitive/secret data or sensitive information hidden in the images.

In advance, load an image using **Pillow (PIL)**.

```shellscript
import numpy as np
from PIL import Image

img = Image.open("example.png")
```

### Basic Information <a href="#basic-information" id="basic-information"></a>

```shellscript
# Filename
img.filename

# Image information
img.info

# Image format (PNG, JPG, etc.)
img.format

# Color mode (RPG, CMYK, etc.)
img.mode

# Image size
img.size

# Bytes
img.tobytes()

# Pixels
np.array(img.getdata())
```

#### Plot Images <a href="#plot-images" id="plot-images"></a>

```shellscript
import matplotlib.pyplot as plt

plt.imshow(img)
plt.axis('off') # Turn off axis and labels
plt.show()
```

### Hidden Information <a href="#hidden-information" id="hidden-information"></a>

Find hidden data in the image by slightly changing.

#### Resize Image & Get Bytes <a href="#resize-image-get-bytes" id="resize-image-get-bytes"></a>

```shellscript
img1 = img.resize((128, 128))
print(img1.tobytes())
```

#### XOR Image Bytes <a href="#xor-image-bytes" id="xor-image-bytes"></a>

```shellscript
# Convert image to bytes
bytes = img.tobytes()

key = 2 # specify the XOR key

xored = []
for byte in bytes:
    xored.append(byte ^ key)
xored_np = np.array(xored)
print(xored_np)
```
