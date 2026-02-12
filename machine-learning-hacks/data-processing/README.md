# Data Processing

## Cluster Analysis for Machine Learning <a href="#cluster-analysis-for-machine-learning" id="cluster-analysis-for-machine-learning"></a>

We can find the number of clusters using methods such as K-means.

### Find Optimal Number of Clusters <a href="#find-optimal-number-of-clusters" id="find-optimal-number-of-clusters"></a>

#### K-means & Elbow Curve <a href="#k-means-elbow-curve" id="k-means-elbow-curve"></a>

Reference: [https://www.kaggle.com/code/jonbown/ai-ctf-submissions?scriptVersionId=105606691\&cellId=39](https://www.kaggle.com/code/jonbown/ai-ctf-submissions?scriptVersionId=105606691\&cellId=39)

We may find the optimal number of clusters by using **K-means** algorithm and observing the **Elbow** graph.

```shellscript
import numpy as np
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt

clusters = np.load("example.npy")

# specify the range of the number of clusters
K = range(1, 10)

distortions = []
for i in K:
    kmeans = KMeans(n_clusters=i)
    kmeans.fit(clusters)
    distortions.append(kmeans.inertia_)

plt.plot(K, distortions)
plt.xlabel("Number of clusters")
plt.ylabel("Distortion")
```

Seeing the output graph, the last point where the distortion (or inertia) drops sharply may be the optimal number of clusters.

### References <a href="#references" id="references"></a>

* [Kaggle](https://www.kaggle.com/competitions/ai-village-ctf)
* [GeeksForGeeks](https://www.geeksforgeeks.org/elbow-method-for-optimal-value-of-k-in-kmeans/)
