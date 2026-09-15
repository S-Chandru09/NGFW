# AI-NGFW Model Graph Report

Inspection-only visualization for lecturer evaluation. All numbers below are copied from existing project JSON files. No models were retrained. No trained model files, datasets, preprocessing outputs, or application source were modified.

Presentation output directory:

`F:\Main_Project\ai_engine\ml\models\visualizations\presentation\`

---

## A. Existing artifacts inspected

### Metrics JSON

| File | Status |
|---|---|
| `ai_engine/ml/models/sklearn/random_forest_metrics.json` | Present |
| `ai_engine/ml/models/sklearn/isolation_forest_metrics.json` | Present |
| `ai_engine/ml/models/sklearn/dbscan_metrics.json` | Present |
| `ai_engine/ml/models/tensorflow/cnn_metrics.json` | Present |

### Metadata JSON

| File | Status |
|---|---|
| `ai_engine/ml/models/sklearn/random_forest_metadata.json` | Present |
| `ai_engine/ml/models/sklearn/isolation_forest_metadata.json` | Present |
| `ai_engine/ml/models/sklearn/dbscan_metadata.json` | Present |
| `ai_engine/ml/models/tensorflow/cnn_metadata.json` | Present |

### Trained models (inspected by filename/size/hash only; not loaded, not overwritten)

| File | Status |
|---|---|
| `random_forest_model.pkl` | Present (322,548,353 bytes) |
| `isolation_forest_model.pkl` | Present (1,473,577 bytes) |
| `dbscan_model.pkl` | Present (1,752,619 bytes) |
| `dbscan_pca_model.pkl` | Present (6,147 bytes) |
| `cnn_encrypted_traffic_model.keras` | Present (1,406,131 bytes) |

### Existing DBSCAN visualizations (originals left unchanged)

| File | Status |
|---|---|
| `ai_engine/ml/models/sklearn/visualizations/dbscan_clusters_train.png` | Present |
| `ai_engine/ml/models/sklearn/visualizations/dbscan_clusters_test.png` | Present |
| `ai_engine/ml/models/sklearn/visualizations/dbscan_true_labels_train.png` | Present |

### Other stored evaluation artifacts

| File | Used for graphs? |
|---|---|
| `dbscan_train_labels.npy` | No. Cluster counts already exist in `dbscan_metrics.json`. |
| `dbscan_test_labels.npy` | No. Same reason. |
| Isolation Forest per-sample scores | Not stored as arrays. Only summary stats exist in metrics JSON. |
| Random Forest / Isolation Forest / CNN prediction files | Not present. |

### Training / visualization scripts inspected (read-only)

- `ai_engine/ml/training/train_random_forest.py`
- `ai_engine/ml/training/train_isolation_forest.py`
- `ai_engine/ml/training/train_dbscan.py` (creates the original DBSCAN PNGs)
- `ai_engine/ml/training/train_cnn.py`

These scripts were not executed.

### Data available vs not available

**Available:** scalar metrics, confusion matrices, classification reports, RF top feature importances, IF ROC-AUC scalar, IF TP/TN/FP/FN, DBSCAN cluster counts and clustering quality scores, CNN epoch-by-epoch training history, CNN confusion matrix.

**Not available:** ROC curve points (FPR/TPR arrays), Isolation Forest prediction/score arrays, feature-importance values beyond the stored RF top-20 list, CNN prediction arrays beyond the stored confusion matrix.

---

## Model inspection summaries

Values are taken from the JSON files named in each section. Missing fields are marked **not stored**.

### 1. Random Forest

| Field | Value | Source |
|---|---|---|
| Model name | `random_forest` | metrics + metadata |
| Algorithm | `RandomForestClassifier` | metrics + metadata |
| Training status | Trained; `trained_at` = 2026-09-03T05:16:43.206722+00:00 | metadata |
| Dataset | CICIDS2017 | metrics + metadata |
| Features | 78 | `feature_count` |
| Classes | 15 | `class_count` + `label_classes` |
| Hyperparameters | n_estimators=200, max_depth=null, min_samples_split=2, min_samples_leaf=1, max_features=sqrt, class_weight=balanced, random_state=42 | metadata |
| Accuracy | 0.9981798179817982 | metrics |
| Precision (macro) | 0.9146751744507089 | metrics |
| Recall (macro) | 0.880485509292987 | metrics |
| F1 (macro) | 0.8934691458254552 | metrics |
| Precision (weighted) | 0.9981302830354775 | metrics |
| Recall (weighted) | 0.9981798179817982 | metrics |
| F1 (weighted) | 0.9981395488694773 | metrics |
| ROC-AUC | **not stored** | — |
| Train samples | 1,999,798 | metrics |
| Test samples | 499,950 | metrics |
| Confusion matrix | 15×15 stored | metrics |
| Top feature importances | 20 features stored | metadata |
| Evaluated at | 2026-09-03T05:16:43.053756+00:00 | metrics |

### 2. Isolation Forest

| Field | Value | Source |
|---|---|---|
| Model name | `isolation_forest` | metrics + metadata |
| Algorithm | `IsolationForest` | metrics + metadata |
| Task | `anomaly_detection` | metrics + metadata |
| Training status | Trained; `trained_at` = 2026-09-03T05:44:09.392967+00:00 | metadata |
| Dataset | CICIDS2017 | metrics + metadata |
| Features | 43 | `feature_count` |
| Classes | Binary evaluation (BENIGN vs all attacks). 15 original labels listed in metadata. | metadata |
| Hyperparameters | n_estimators=200, max_samples=auto, contamination=0.1, max_features=1.0, bootstrap=false, random_state=42, train_on_benign_only=true | metadata |
| Accuracy | 0.8475587558755876 | metrics |
| Precision | 0.5490601771267803 | metrics |
| Recall / detection rate | 0.5888395792241946 | metrics |
| F1 | 0.5682545617285 | metrics |
| ROC-AUC | 0.7885440140566983 (scalar only; no curve points) | metrics |
| FPR | 0.09931191444015296 | metrics |
| FNR | 0.4111604207758054 | metrics |
| TP / TN / FP / FN | 50155 / 373582 / 41192 / 35021 | metrics |
| Train samples | 1,999,798 | metrics |
| Test samples | 499,950 | metrics |
| Evaluated at | 2026-09-03T05:44:09.389969+00:00 | metrics |

### 3. DBSCAN

| Field | Value | Source |
|---|---|---|
| Model name | `dbscan` | metrics + metadata |
| Algorithm | `DBSCAN` | metrics + metadata |
| Task | `density_clustering` | metrics + metadata |
| Training status | Trained; `trained_at` = 2026-09-03T06:05:00.684158+00:00 | metadata |
| Dataset | CICIDS2017 | metrics + metadata |
| Features | 15 PCA components | `feature_count` + `feature_names` |
| Classes | Clustering model; 15 CICIDS labels listed for reference only | metadata |
| Hyperparameters | eps=0.8, min_samples=5, metric=euclidean, algorithm=auto, leaf_size=30, max_clustering_samples=25000 | metadata |
| Accuracy / Precision / Recall / F1 / ROC-AUC | **not stored** (not a classifier evaluation) | — |
| Cluster count | 108 | metrics |
| Noise count (train) | 139,043 | metrics |
| Noise ratio | 0.06952852238076046 | metrics |
| Silhouette | 0.2630903422832489 | metrics |
| Calinski-Harabasz | 906.5241088867188 | metrics |
| Davies-Bouldin | 0.5831145757893809 | metrics |
| Adjusted Rand Index | 0.11488446404149166 | metrics |
| Normalized Mutual Info | 0.2767970232873624 | metrics |
| Train anomaly detection rate | 0.06873455395037305 | metrics |
| Test anomaly detection rate | 0.07102939795247487 | metrics |
| Train samples | 1,999,798 | metrics |
| Test samples | 499,950 | metrics |
| Test noise | 34,621 | `test_cluster_distribution.noise` |
| Evaluated at | 2026-09-03T06:05:00.681147+00:00 | metrics |

### 4. CNN (encrypted-traffic simulation)

| Field | Value | Source |
|---|---|---|
| Model name | `cnn_encrypted_traffic` | metrics + metadata |
| Algorithm | Convolutional Neural Network | metrics + metadata |
| Task | `encrypted_traffic_simulation` | metrics + metadata |
| Training status | Trained; `trained_at` = 2026-09-03T06:45:45.964227+00:00 | metadata |
| Dataset | CICIDS2017 | metrics + metadata |
| Input | 78 flow features reshaped to 9×9×1 | metadata `input_shape` / `grid_shape` |
| Classes | 15 | `class_count` |
| Hyperparameters | epochs=25, batch_size=128, learning_rate=0.001, validation_split=0.1, early_stopping_patience=5, use_class_weights=true, random_state=42 | metadata |
| Stored history length | 11 epochs (early stopping; full 25-epoch run was not stored) | `training_history` |
| Accuracy | 0.6956 | metrics |
| Precision (macro) | 0.2478020627295267 | metrics |
| Recall (macro) | 0.6242681244363255 | metrics |
| F1 (macro) | 0.27498676757235135 | metrics |
| Precision (weighted) | 0.9398812122177802 | metrics |
| Recall (weighted) | 0.6956 | metrics |
| F1 (weighted) | 0.7834195045100495 | metrics |
| ROC-AUC | **not stored** | — |
| Train samples | 150,000 | metrics |
| Test samples | 30,000 | metrics |
| Confusion matrix | 15×15 stored | metrics |
| Epoch history | accuracy, loss, val_accuracy, val_loss, learning_rate | metrics |
| Evaluated at | 2026-09-03T06:45:45.962553+00:00 | metrics |

CNN class 8 (Heartbleed) and class 13 (Web Attack - Sql Injection) have **support 0** in the stored test classification report.

---

## B. Graphs successfully generated

All new files are in `ai_engine/ml/models/visualizations/presentation/`.

| Graph file | Type |
|---|---|
| `rf_performance_metrics.png` | New |
| `rf_feature_importance.png` | New |
| `rf_per_class_f1.png` | New |
| `rf_confusion_matrix.png` | New |
| `if_performance_metrics.png` | New |
| `if_detection_rates.png` | New |
| `if_confusion_matrix.png` | New |
| `dbscan_clusters_train.png` | Presentation copy of existing PNG |
| `dbscan_clusters_test.png` | Presentation copy of existing PNG |
| `dbscan_true_labels_train.png` | Presentation copy of existing PNG |
| `dbscan_cluster_distribution_train.png` | New (from stored counts) |
| `dbscan_clustered_vs_noise_test.png` | New (from stored counts) |
| `dbscan_quality_metrics.png` | New |
| `cnn_accuracy_curve.png` | New |
| `cnn_loss_curve.png` | New |
| `cnn_performance_metrics.png` | New |
| `cnn_per_class_f1.png` | New |
| `cnn_confusion_matrix.png` | New |
| `model_comparison.png` | New |
| `generate_presentation_graphs.py` | Generator script (JSON → PNG only) |
| `MODEL_GRAPH_REPORT.md` | This report |

---

## C. Graphs that could not be generated, and why

| Requested graph | Why it was not generated |
|---|---|
| Isolation Forest ROC curve | `roc_auc` is stored as a single number (0.7885440140566983). No FPR/TPR arrays or per-sample scores exist. Regenerating scores would require loading the model and test data, which this task forbids. |
| Random Forest ROC-AUC / ROC curve | Not present in `random_forest_metrics.json`. |
| CNN ROC curve | Not present in `cnn_metrics.json`. |
| DBSCAN accuracy / precision / recall / F1 | Not stored. DBSCAN was evaluated as clustering, not as a 15-class classifier. |
| Additional RF feature-importance bars beyond the stored top 20 | Only `top_feature_importances` (20 entries) exists in metadata. The pickle was not loaded. |
| Isolation Forest feature importance | Isolation Forest does not store feature importances in the project JSON files. |
| Extra CNN epochs (12–25) | History contains 11 epochs only. Retraining is forbidden. |

---

## D. Exact source file for every graph

| Graph | Source |
|---|---|
| `rf_performance_metrics.png` | `sklearn/random_forest_metrics.json` → `metrics` |
| `rf_feature_importance.png` | `sklearn/random_forest_metadata.json` → `top_feature_importances` |
| `rf_per_class_f1.png` | `sklearn/random_forest_metrics.json` → `classification_report` and `sklearn/random_forest_metadata.json` → `label_classes` |
| `rf_confusion_matrix.png` | `sklearn/random_forest_metrics.json` → `confusion_matrix` |
| `if_performance_metrics.png` | `sklearn/isolation_forest_metrics.json` → `metrics` |
| `if_detection_rates.png` | `sklearn/isolation_forest_metrics.json` → `metrics` |
| `if_confusion_matrix.png` | `sklearn/isolation_forest_metrics.json` → `confusion_matrix` |
| `dbscan_clusters_train.png` | copy of `sklearn/visualizations/dbscan_clusters_train.png` |
| `dbscan_clusters_test.png` | copy of `sklearn/visualizations/dbscan_clusters_test.png` |
| `dbscan_true_labels_train.png` | copy of `sklearn/visualizations/dbscan_true_labels_train.png` |
| `dbscan_cluster_distribution_train.png` | `sklearn/dbscan_metrics.json` → `train_cluster_distribution` |
| `dbscan_clustered_vs_noise_test.png` | `sklearn/dbscan_metrics.json` → `test_cluster_distribution` |
| `dbscan_quality_metrics.png` | `sklearn/dbscan_metrics.json` → `metrics` |
| `cnn_accuracy_curve.png` | `tensorflow/cnn_metrics.json` → `training_history.accuracy` / `val_accuracy` |
| `cnn_loss_curve.png` | `tensorflow/cnn_metrics.json` → `training_history.loss` / `val_loss` |
| `cnn_performance_metrics.png` | `tensorflow/cnn_metrics.json` → `metrics` |
| `cnn_per_class_f1.png` | `tensorflow/cnn_metrics.json` → `classification_report` and `tensorflow/cnn_metadata.json` → `label_classes` |
| `cnn_confusion_matrix.png` | `tensorflow/cnn_metrics.json` → `confusion_matrix` |
| `model_comparison.png` | RF, IF, CNN, DBSCAN metrics JSON files listed above |

---

## E. Exact metric values used

### Random Forest (`random_forest_metrics.json`)

- accuracy = 0.9981798179817982
- precision_macro = 0.9146751744507089
- recall_macro = 0.880485509292987
- f1_macro = 0.8934691458254552
- precision_weighted = 0.9981302830354775
- recall_weighted = 0.9981798179817982
- f1_weighted = 0.9981395488694773
- train_samples = 1999798
- test_samples = 499950
- feature_count = 78
- class_count = 15

Top feature importances (`random_forest_metadata.json`):

- Destination_Port = 0.05870291448984157
- Init_Win_bytes_backward = 0.050951194064742945
- Fwd_Packet_Length_Max = 0.02865485781886752
- Bwd_Packets_s = 0.02684789616176566
- Bwd_Header_Length = 0.02505294916147241
- Flow_Duration = 0.024399027246681432
- min_seg_size_forward = 0.02421764008761587
- Bwd_Packet_Length_Max = 0.02414903655665779
- Total_Length_of_Bwd_Packets = 0.023162864452983958
- Flow_IAT_Std = 0.0228011828761872
- Flow_IAT_Mean = 0.021979463758153996
- Max_Packet_Length = 0.021868730894114688
- Avg_Bwd_Segment_Size = 0.021576090084150127
- Flow_IAT_Max = 0.021408080380788185
- Flow_Packets_s = 0.021319760281162347
- Fwd_IAT_Total = 0.021306068634266394
- Init_Win_bytes_forward = 0.02127626996900844
- Bwd_Packet_Length_Mean = 0.02108038061528747
- Fwd_IAT_Mean = 0.02097241178788968
- Packet_Length_Mean = 0.020387799740148375

### Isolation Forest (`isolation_forest_metrics.json`)

- accuracy = 0.8475587558755876
- precision = 0.5490601771267803
- recall = 0.5888395792241946
- f1_score = 0.5682545617285
- roc_auc = 0.7885440140566983
- detection_rate = 0.5888395792241946
- false_positive_rate = 0.09931191444015296
- false_negative_rate = 0.4111604207758054
- true_positives = 50155
- true_negatives = 373582
- false_positives = 41192
- false_negatives = 35021
- train_samples = 1999798
- test_samples = 499950
- feature_count = 43

Confusion matrix: [[373582, 41192], [35021, 50155]]

### DBSCAN (`dbscan_metrics.json`)

- cluster_count = 108
- noise_count = 139043
- noise_ratio = 0.06952852238076046
- silhouette_score = 0.2630903422832489
- calinski_harabasz_score = 906.5241088867188
- davies_bouldin_score = 0.5831145757893809
- adjusted_rand_index = 0.11488446404149166
- normalized_mutual_info = 0.2767970232873624
- train_samples = 1999798
- test_samples = 499950
- feature_count = 15
- test noise = 34621
- test clustered samples = 499950 − 34621 = 465329 (sum of stored non-noise test cluster counts)

Largest train clusters used in the distribution graph (exact stored counts): cluster_0=683465, cluster_4=401580, cluster_1=345833, cluster_8=67993, cluster_2=42337, cluster_17=40129, cluster_7=33577, cluster_10=31573, cluster_6=25401, cluster_24=19530, cluster_5=18337, cluster_15=14641. Remaining 96 clusters were summed for readability; no counts were invented.

### CNN (`cnn_metrics.json`)

- accuracy = 0.6956
- precision_macro = 0.2478020627295267
- recall_macro = 0.6242681244363255
- f1_macro = 0.27498676757235135
- precision_weighted = 0.9398812122177802
- recall_weighted = 0.6956
- f1_weighted = 0.7834195045100495
- train_samples = 150000
- test_samples = 30000
- class_count = 15

Training history (11 epochs):

accuracy = [0.5734962821006775, 0.5893259048461914, 0.6140000224113464, 0.633207380771637, 0.6120148301124573, 0.6224963068962097, 0.6530740857124329, 0.6055333614349365, 0.6156814694404602, 0.639118492603302, 0.6683333516120911]

val_accuracy = [0.6149333119392395, 0.6723999977111816, 0.6586666703224182, 0.6952666640281677, 0.6437333226203918, 0.7030666470527649, 0.7026000022888184, 0.6363999843597412, 0.6623333096504211, 0.7023333311080933, 0.6867333054542542]

loss = [2.219799280166626, 1.894514799118042, 1.3923561573028564, 1.4240249395370483, 1.0601543188095093, 2.315293788909912, 0.876491129398346, 1.3635830879211426, 1.6316876411437988, 0.5242974758148193, 0.6562979221343994]

val_loss = [1.2892783880233765, 1.0834356546401978, 1.0639654397964478, 0.9602935910224915, 1.1981821060180664, 0.9038933515548706, 1.0285348892211914, 1.1549760103225708, 1.0922514200210571, 0.9657802581787109, 1.0430941581726074]

---

## F. What each graph means

### Random Forest

- **rf_performance_metrics.png:** Overall test scores. Weighted metrics are high because BENIGN dominates the test set. Macro metrics are lower because rare classes are averaged equally.
- **rf_feature_importance.png:** Which flow features the trained forest used most. Destination port and backward initial window size rank highest among the stored top 20.
- **rf_per_class_f1.png:** Class-by-class F1. Frequent attacks (DDoS, DoS Hulk, PortScan) score near 1.0; rare web attacks score much lower.
- **rf_confusion_matrix.png:** Where the 15-class classifier placed each test sample. Stored counts only; the model was not re-run.

### Isolation Forest

- **if_performance_metrics.png:** Binary anomaly-detection scores on the same CICIDS2017 test split. Precision/recall/F1 are for attack-as-positive, not 15-class labels.
- **if_detection_rates.png:** Detection rate vs false-positive rate vs false-negative rate from stored TP/TN/FP/FN-derived rates.
- **if_confusion_matrix.png:** TN=373582, FP=41192, FN=35021, TP=50155.

### DBSCAN

- **dbscan_clusters_*.png / dbscan_true_labels_train.png:** Original 2D PCA scatter plots produced during training. Copies only.
- **dbscan_cluster_distribution_train.png:** How training samples are split across noise and clusters.
- **dbscan_clustered_vs_noise_test.png:** Test-set noise vs clustered assignment.
- **dbscan_quality_metrics.png:** Internal (silhouette, Davies-Bouldin, Calinski-Harabasz) and label-agreement (ARI, NMI) clustering scores.

### CNN

- **cnn_accuracy_curve.png / cnn_loss_curve.png:** Epoch history actually stored after training (11 epochs).
- **cnn_performance_metrics.png:** Test scores on the encrypted-traffic simulation task (flow features as 9×9 tensors, 30,000 test samples).
- **cnn_per_class_f1.png:** Per-class F1, including classes with support 0.
- **cnn_confusion_matrix.png:** 15×15 stored test confusion matrix.

### Comparison

- **model_comparison.png:** Places RF, Isolation Forest, and CNN beside each other using similarly named scores, and shows DBSCAN clustering scores separately. These models solve different problems.

---

## G. One- or two-sentence lecturer explanations

**rf_performance_metrics.png:**  
“This is the Random Forest test result on CICIDS2017: overall accuracy is 99.82%, while macro F1 is 89.35% because rare classes are counted equally.”

**rf_feature_importance.png:**  
“These importances were saved after training. Destination port and TCP window-related features contribute most among the stored top 20.”

**rf_per_class_f1.png:**  
“The forest is strong on frequent attacks and weaker on low-support web attacks, which is expected from the class imbalance in CICIDS2017.”

**rf_confusion_matrix.png:**  
“This is the stored 15-class confusion matrix on 499,950 test flows. No predictions were regenerated for this slide.”

**if_performance_metrics.png:**  
“Isolation Forest is an unsupervised anomaly detector trained on benign traffic. On the test set it reaches 84.76% accuracy, F1 0.568, and ROC-AUC 0.789.”

**if_detection_rates.png:**  
“It detects 58.88% of attacks, with a 9.93% false-positive rate and a 41.12% false-negative rate, using the stored evaluation counts.”

**if_confusion_matrix.png:**  
“The binary confusion matrix is taken from isolation_forest_metrics.json: 50,155 true anomalies caught and 41,192 false alarms.”

**dbscan_clusters_train.png:**  
“This original training visualization shows DBSCAN clusters in the first two PCA components, including noise points.”

**dbscan_clusters_test.png:**  
“The matching original test-set cluster plot. The PNG was copied, not regenerated from the model.”

**dbscan_true_labels_train.png:**  
“This original plot shows true CICIDS2017 labels in the same PCA space, for comparison with the DBSCAN cluster plot.”

**dbscan_cluster_distribution_train.png:**  
“From stored counts: 108 clusters and 139,043 noise points. A few large clusters hold most of the 1,999,798 training samples.”

**dbscan_clustered_vs_noise_test.png:**  
“On the test set, 34,621 of 499,950 samples were labelled noise (6.92% from the stored noise count).”

**dbscan_quality_metrics.png:**  
“DBSCAN was scored as clustering, not classification: silhouette 0.263, ARI 0.115, NMI 0.277, noise ratio 6.95%.”

**cnn_accuracy_curve.png:**  
“This curve is the 11-epoch accuracy history stored in cnn_metrics.json. The model was configured for 25 epochs with early stopping; we did not retrain.”

**cnn_loss_curve.png:**  
“This is the stored training and validation loss for those same 11 epochs.”

**cnn_performance_metrics.png:**  
“The CNN is a 15-class model on simulated encrypted-traffic tensors. Test accuracy is 69.56%; macro F1 is 0.275 because rare classes and class weighting pull the average down.”

**cnn_per_class_f1.png:**  
“Per-class F1 comes from the stored classification report. Heartbleed and SQL Injection have zero test support in this CNN split.”

**cnn_confusion_matrix.png:**  
“This confusion matrix is stored in cnn_metrics.json for 30,000 test samples. Predictions were not re-run.”

**model_comparison.png:**  
“Random Forest, Isolation Forest, DBSCAN, and CNN have different jobs: 15-class supervised detection, unsupervised anomaly detection, density clustering, and encrypted-traffic simulation. Shared metric names are shown for reporting, but they are not equivalent scientific rankings.”

---

## Phase 4 notes (verification intent)

Verification after generation:

- PNG files exist in the presentation directory and open as images.
- Trained model files were not loaded for inference and were not overwritten.
- Dataset and preprocessing outputs were not used or changed.
- Application source, Docker, MongoDB, backend, frontend, and AI-engine runtime code were not changed.
- Training scripts were not executed.
- Git was checked for status only; nothing was committed or pushed.
