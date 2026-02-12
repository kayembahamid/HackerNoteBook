# Read HDF5 (H5) File

HDF5 is a file format of the HDF (Hierarchical Data Format) which is designed to store and organize large amounts of data.

### TensorFlow <a href="#tensorflow" id="tensorflow"></a>

```shellscript
import tensorflow as tf

model = tf.keras.models.load_model("example.h5")
model.summary()
```

### h5py <a href="#h5py" id="h5py"></a>

**h5py** is the Python library to read and write HDF5 files.

#### Installation <a href="#installation" id="installation"></a>

```shellscript
pip3 install h5py
```

#### Read HDF5 (H5) <a href="#read-hdf5-h5" id="read-hdf5-h5"></a>

Then run the following script.

```shellscript
import h5py

with h5py.File('example.hdf5', 'r') as f:
    # Get all keys
    print("All keys: %s" % f.keys())
    # Get an object
    print("Object: " % f["key_name"])
    print("Object keys: " % f["key_name"].keys())
    print("Sub object: " % f["key_name"]["sub_key_name"])
```

#### Write HDF5 (H5) <a href="#write-hdf5-h5" id="write-hdf5-h5"></a>

```shellscript
import h5py
import numpy as np

data_matrix = np.random.uniform(-1, 1, size=(10, 3))

with h5py.File('example.hdf5', 'w') as f:
    f.create_dataset("dataset_name", data=data_matrix)
```

### References <a href="#references" id="references"></a>

* [h5py](https://docs.h5py.org/en/latest/quick.html)
* [StackOverflow](https://stackoverflow.com/questions/28170623/how-to-read-hdf5-files-in-python)
