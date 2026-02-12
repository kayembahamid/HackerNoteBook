# Dimensionality Reduction for Machine Learning

## Dimensionality Reduction for Machine Learning <a href="#dimensionality-reduction-for-machine-learning" id="dimensionality-reduction-for-machine-learning"></a>

Dimensionality Reduction is a data processing to make machine learning models easier to train.

### PCA (Principal Component Analysis) <a href="#pca-principal-component-analysis" id="pca-principal-component-analysis"></a>

Reference: [https://www.kaggle.com/code/jonbown/ai-ctf-submissions?scriptVersionId=105606691\&cellId=42](https://www.kaggle.com/code/jonbown/ai-ctf-submissions?scriptVersionId=105606691\&cellId=42)

we use **PCA** to find the optimal dimensions for data.

```shellscript
import numpy as np
from sklearn.decomposition import PCA

data = np.load("example.npy")

for i in range(1, 10):
    pca = PCA(n_components=i)
    principal_components = pca.fit_transform(data)
    print(pca.explained_variance_ratio_)
```

### References <a href="#references" id="references"></a>

* [Kaggle](https://www.kaggle.com/competitions/ai-village-ctf)
