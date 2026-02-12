# IMINT (Image Intelligence) and GEOINT (Geospatial Intelligence)

IMINT and GEOINT are types of OSINT to reveal desired information from analyzing images.

### Basic Investigation <a href="#basic-investigation" id="basic-investigation"></a>

```shellscript
open example.jpg
exiftool example.jpg
```

### Gather Information From Search Engine <a href="#gather-information-from-search-engine" id="gather-information-from-search-engine"></a>

Search the keyword which is found in the image.

* Name
* Location (country, city, etc.)
* When does it open

### Reverse Image Search <a href="#reverse-image-search" id="reverse-image-search"></a>

Upload the image in each search engine.

* [**Bing Images**](https://www.bing.com/?scope=images)
*   [**Google Images**](https://www.google.com/imghp)

    Click the “Search by image” icon and upload the image.
* [**Yandex Images**](http://yandex.com/images)

### Video (mp4) Geolocation <a href="#video-mp4-geolocation" id="video-mp4-geolocation"></a>

FFmpeg extracts every single frame from a video.

```
# -i: input file
# %06d: followed by six digits e.g. img_000001.png, img_000002.png, etc.
# -hide_banner: hide unnecessary text.
# -r: frame rate (e.g. 1 frame per second)
ffmpeg -i example.mp4 -r 1 img_%06d.png -hide_banner
```

