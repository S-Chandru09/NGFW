"""Generate presentation graphs from existing metrics/metadata JSON only.

Does not load, modify, or retrain any model files.
Does not read or write dataset/preprocessing outputs.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

ROOT = Path(r"F:\Main_Project\ai_engine\ml\models")
SKLEARN = ROOT / "sklearn"
TF = ROOT / "tensorflow"
OUT = ROOT / "visualizations" / "presentation"
EXISTING_DBSCAN_VIZ = SKLEARN / "visualizations"

plt.rcParams.update(
    {
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.grid": True,
        "grid.alpha": 0.25,
        "font.size": 11,
        "axes.titlesize": 14,
        "axes.labelsize": 12,
        "legend.fontsize": 10,
        "figure.dpi": 140,
        "savefig.dpi": 160,
        "savefig.bbox": "tight",
        "axes.spines.top": False,
        "axes.spines.right": False,
    }
)

RF_COLOR = "#1f4e79"
IF_COLOR = "#c45911"
DB_COLOR = "#548235"
CNN_COLOR = "#7030a0"
ACCENT = "#2e75b6"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def clean_label(name: str) -> str:
    return name.replace("\ufffd", "-").replace("\u0000", "")


def savefig(fig: plt.Figure, name: str) -> Path:
    path = OUT / name
    fig.savefig(path)
    plt.close(fig)
    print(f"Wrote {path}")
    return path


def annotate_bars(ax, bars, values, as_percent: bool = True) -> None:
    for bar, value in zip(bars, values):
        height = bar.get_height()
        label = f"{value * 100:.2f}%" if as_percent else f"{value:.3f}"
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            label,
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="medium",
        )


def plot_metric_bars(title: str, labels: list[str], values: list[float], color: str, filename: str, ylabel: str) -> None:
    fig, ax = plt.subplots(figsize=(10, 5.5))
    bars = ax.bar(labels, values, color=color, edgecolor="black", linewidth=0.6, width=0.65)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    annotate_bars(ax, bars, values, as_percent=True)
    ax.set_axisbelow(True)
    savefig(fig, filename)


def plot_confusion_matrix(
    matrix: list[list[int]],
    class_names: list[str],
    title: str,
    filename: str,
    figsize: tuple[float, float],
) -> None:
    cm = np.array(matrix, dtype=float)
    fig, ax = plt.subplots(figsize=figsize)
    im = ax.imshow(cm, cmap="Blues")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    ax.set_xticks(range(len(class_names)))
    ax.set_yticks(range(len(class_names)))
    ax.set_xticklabels(class_names, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(class_names, fontsize=8)
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    ax.set_title(title)
    ax.grid(False)
    if cm.size <= 9:
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, f"{int(cm[i, j]):,}", ha="center", va="center", fontsize=10)
    savefig(fig, filename)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    rf_metrics = load_json(SKLEARN / "random_forest_metrics.json")
    rf_meta = load_json(SKLEARN / "random_forest_metadata.json")
    if_metrics = load_json(SKLEARN / "isolation_forest_metrics.json")
    db_metrics = load_json(SKLEARN / "dbscan_metrics.json")
    cnn_metrics = load_json(TF / "cnn_metrics.json")
    cnn_meta = load_json(TF / "cnn_metadata.json")

    rf_m = rf_metrics["metrics"]
    if_m = if_metrics["metrics"]
    cnn_m = cnn_metrics["metrics"]
    db_m = db_metrics["metrics"]

    # --- Random Forest ---
    plot_metric_bars(
        "Random Forest Test Performance (CICIDS2017)",
        ["Accuracy", "Precision\n(macro)", "Recall\n(macro)", "F1\n(macro)", "Precision\n(weighted)", "Recall\n(weighted)", "F1\n(weighted)"],
        [
            rf_m["accuracy"],
            rf_m["precision_macro"],
            rf_m["recall_macro"],
            rf_m["f1_macro"],
            rf_m["precision_weighted"],
            rf_m["recall_weighted"],
            rf_m["f1_weighted"],
        ],
        RF_COLOR,
        "rf_performance_metrics.png",
        "Score (0-1)",
    )

    importances = rf_meta["top_feature_importances"]
    feat_names = [item["feature"] for item in importances]
    feat_vals = [item["importance"] for item in importances]
    fig, ax = plt.subplots(figsize=(11, 7))
    y_pos = np.arange(len(feat_names))
    ax.barh(y_pos, feat_vals, color=RF_COLOR, edgecolor="black", linewidth=0.4)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(feat_names)
    ax.invert_yaxis()
    ax.set_xlabel("Feature importance (Gini / mean decrease in impurity)")
    ax.set_title("Random Forest Top Feature Importances (stored after training)")
    ax.set_xlim(0, max(feat_vals) * 1.18)
    for y, value in zip(y_pos, feat_vals):
        ax.text(value + 0.0004, y, f"{value:.4f}", va="center", fontsize=8)
    savefig(fig, "rf_feature_importance.png")

    report = rf_metrics["classification_report"]
    class_names = [clean_label(name) for name in rf_meta["label_classes"]]
    f1_scores = [report[raw]["f1-score"] for raw in rf_meta["label_classes"]]
    supports = [int(report[raw]["support"]) for raw in rf_meta["label_classes"]]
    fig, ax = plt.subplots(figsize=(12, 6.5))
    bars = ax.bar(range(len(class_names)), f1_scores, color=RF_COLOR, edgecolor="black", linewidth=0.4)
    ax.set_xticks(range(len(class_names)))
    ax.set_xticklabels(class_names, rotation=45, ha="right")
    ax.set_ylabel("F1-score")
    ax.set_ylim(0, 1.12)
    ax.set_title("Random Forest Per-Class F1-score (test set)")
    for bar, value, support in zip(bars, f1_scores, supports):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.02,
            f"{value:.2f}\nn={support}",
            ha="center",
            va="bottom",
            fontsize=7,
        )
    savefig(fig, "rf_per_class_f1.png")

    plot_confusion_matrix(
        rf_metrics["confusion_matrix"],
        class_names,
        "Random Forest Confusion Matrix (test set, 499,950 samples)",
        "rf_confusion_matrix.png",
        (11, 9),
    )

    # --- Isolation Forest ---
    plot_metric_bars(
        "Isolation Forest Anomaly Detection Performance (CICIDS2017 test set)",
        ["Accuracy", "Precision", "Recall\n(detection rate)", "F1-score", "ROC-AUC"],
        [if_m["accuracy"], if_m["precision"], if_m["recall"], if_m["f1_score"], if_m["roc_auc"]],
        IF_COLOR,
        "if_performance_metrics.png",
        "Score (0-1)",
    )

    plot_metric_bars(
        "Isolation Forest Error and Detection Rates (test set)",
        ["Detection rate\n(TPR / Recall)", "False positive\nrate", "False negative\nrate"],
        [if_m["detection_rate"], if_m["false_positive_rate"], if_m["false_negative_rate"]],
        IF_COLOR,
        "if_detection_rates.png",
        "Rate (0-1)",
    )

    plot_confusion_matrix(
        if_metrics["confusion_matrix"],
        ["Normal (BENIGN)", "Anomaly (attack)"],
        "Isolation Forest Confusion Matrix (binary: normal vs anomaly)",
        "if_confusion_matrix.png",
        (7.5, 6),
    )

    # --- DBSCAN copies ---
    copies = {
        "dbscan_clusters_train.png": EXISTING_DBSCAN_VIZ / "dbscan_clusters_train.png",
        "dbscan_clusters_test.png": EXISTING_DBSCAN_VIZ / "dbscan_clusters_test.png",
        "dbscan_true_labels_train.png": EXISTING_DBSCAN_VIZ / "dbscan_true_labels_train.png",
    }
    for dest_name, src in copies.items():
        dest = OUT / dest_name
        shutil.copy2(src, dest)
        print(f"Copied {src} -> {dest}")

    train_dist = db_metrics["train_cluster_distribution"]
    noise = train_dist["noise"]
    cluster_items = sorted(
        ((k, v) for k, v in train_dist.items() if k != "noise"),
        key=lambda item: item[1],
        reverse=True,
    )
    top_n = 12
    top = cluster_items[:top_n]
    other_sum = sum(value for _, value in cluster_items[top_n:])
    labels = ["Noise"] + [name.replace("cluster_", "C") for name, _ in top] + [f"Other clusters\n({len(cluster_items) - top_n} clusters)"]
    values = [noise] + [value for _, value in top] + [other_sum]
    colors = ["#7f7f7f"] + [DB_COLOR] * top_n + ["#a9d08e"]
    fig, ax = plt.subplots(figsize=(12, 6.2))
    bars = ax.bar(range(len(labels)), values, color=colors, edgecolor="black", linewidth=0.4)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=40, ha="right")
    ax.set_ylabel("Number of training samples")
    ax.set_title("DBSCAN Train Cluster / Noise Distribution (from stored counts)")
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{int(x):,}"))
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:,}",
            ha="center",
            va="bottom",
            fontsize=7,
            rotation=0,
        )
    legend_handles = [
        Patch(facecolor="#7f7f7f", edgecolor="black", label="Noise (label -1)"),
        Patch(facecolor=DB_COLOR, edgecolor="black", label="Largest 12 clusters"),
        Patch(facecolor="#a9d08e", edgecolor="black", label="Remaining 96 clusters combined"),
    ]
    ax.legend(handles=legend_handles, loc="upper right")
    savefig(fig, "dbscan_cluster_distribution_train.png")

    test_dist = db_metrics["test_cluster_distribution"]
    test_noise = test_dist["noise"]
    test_cluster_sum = sum(v for k, v in test_dist.items() if k != "noise")
    fig, ax = plt.subplots(figsize=(8, 5.5))
    bars = ax.bar(
        ["Assigned to a cluster", "Noise"],
        [test_cluster_sum, test_noise],
        color=[DB_COLOR, "#7f7f7f"],
        edgecolor="black",
        width=0.55,
    )
    ax.set_ylabel("Number of test samples")
    ax.set_title("DBSCAN Test Set: Clustered vs Noise")
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{int(x):,}"))
    for bar, value in zip(bars, [test_cluster_sum, test_noise]):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:,}\n({value / db_metrics['test_samples'] * 100:.2f}%)",
            ha="center",
            va="bottom",
            fontsize=10,
        )
    ax.set_ylim(0, max(test_cluster_sum, test_noise) * 1.18)
    savefig(fig, "dbscan_clustered_vs_noise_test.png")

    fig, ax = plt.subplots(figsize=(10, 5.5))
    db_labels = ["Silhouette", "Adjusted Rand\nIndex", "Normalized\nMutual Info", "Noise ratio"]
    db_values = [
        db_m["silhouette_score"],
        db_m["adjusted_rand_index"],
        db_m["normalized_mutual_info"],
        db_m["noise_ratio"],
    ]
    bars = ax.bar(db_labels, db_values, color=DB_COLOR, edgecolor="black", linewidth=0.6, width=0.6)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score (0-1 scale)")
    ax.set_title("DBSCAN Clustering Quality Metrics (stored evaluation)")
    annotate_bars(ax, bars, db_values, as_percent=False)
    note = (
        f"Davies-Bouldin = {db_m['davies_bouldin_score']:.4f} (lower is better; not 0-1).\n"
        f"Calinski-Harabasz = {db_m['calinski_harabasz_score']:.2f} (higher is better; unbounded)."
    )
    ax.text(0.02, 0.98, note, transform=ax.transAxes, va="top", fontsize=9)
    savefig(fig, "dbscan_quality_metrics.png")

    # --- CNN ---
    history = cnn_metrics["training_history"]
    epochs = np.arange(1, len(history["accuracy"]) + 1)
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.plot(epochs, history["accuracy"], marker="o", color=CNN_COLOR, label="Training accuracy")
    ax.plot(epochs, history["val_accuracy"], marker="s", color="#ed7d31", label="Validation accuracy")
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Accuracy")
    ax.set_title("CNN Training / Validation Accuracy (from stored history)")
    ax.set_xticks(epochs)
    ax.set_ylim(0.5, 0.8)
    ax.legend()
    savefig(fig, "cnn_accuracy_curve.png")

    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.plot(epochs, history["loss"], marker="o", color=CNN_COLOR, label="Training loss")
    ax.plot(epochs, history["val_loss"], marker="s", color="#ed7d31", label="Validation loss")
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Loss")
    ax.set_title("CNN Training / Validation Loss (from stored history)")
    ax.set_xticks(epochs)
    ax.legend()
    savefig(fig, "cnn_loss_curve.png")

    plot_metric_bars(
        "CNN Encrypted-Traffic Simulation Test Performance",
        ["Accuracy", "Precision\n(macro)", "Recall\n(macro)", "F1\n(macro)", "Precision\n(weighted)", "Recall\n(weighted)", "F1\n(weighted)"],
        [
            cnn_m["accuracy"],
            cnn_m["precision_macro"],
            cnn_m["recall_macro"],
            cnn_m["f1_macro"],
            cnn_m["precision_weighted"],
            cnn_m["recall_weighted"],
            cnn_m["f1_weighted"],
        ],
        CNN_COLOR,
        "cnn_performance_metrics.png",
        "Score (0-1)",
    )

    cnn_classes = [clean_label(name) for name in cnn_meta["label_classes"]]
    cnn_report = cnn_metrics["classification_report"]
    cnn_f1 = []
    cnn_support = []
    for idx, name in enumerate(cnn_classes):
        entry = cnn_report[str(idx)]
        cnn_f1.append(entry["f1-score"])
        cnn_support.append(int(entry["support"]))
    fig, ax = plt.subplots(figsize=(12, 6.5))
    bars = ax.bar(range(len(cnn_classes)), cnn_f1, color=CNN_COLOR, edgecolor="black", linewidth=0.4)
    ax.set_xticks(range(len(cnn_classes)))
    ax.set_xticklabels(cnn_classes, rotation=45, ha="right")
    ax.set_ylabel("F1-score")
    ax.set_ylim(0, 1.18)
    ax.set_title("CNN Per-Class F1-score (test set; classes 8 and 13 have support 0)")
    for bar, value, support in zip(bars, cnn_f1, cnn_support):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.02,
            f"{value:.2f}\nn={support}",
            ha="center",
            va="bottom",
            fontsize=7,
        )
    savefig(fig, "cnn_per_class_f1.png")

    plot_confusion_matrix(
        cnn_metrics["confusion_matrix"],
        cnn_classes,
        "CNN Confusion Matrix (encrypted-traffic simulation test set, 30,000 samples)",
        "cnn_confusion_matrix.png",
        (11, 9),
    )

    # --- Model comparison ---
    fig, axes = plt.subplots(1, 2, figsize=(14.5, 6.2), gridspec_kw={"width_ratios": [1.35, 1]})

    metric_names = ["Accuracy", "Precision", "Recall", "F1"]
    rf_vals = [rf_m["accuracy"], rf_m["precision_macro"], rf_m["recall_macro"], rf_m["f1_macro"]]
    if_vals = [if_m["accuracy"], if_m["precision"], if_m["recall"], if_m["f1_score"]]
    cnn_vals = [cnn_m["accuracy"], cnn_m["precision_macro"], cnn_m["recall_macro"], cnn_m["f1_macro"]]
    x = np.arange(len(metric_names))
    width = 0.25
    ax = axes[0]
    b1 = ax.bar(x - width, rf_vals, width, label="Random Forest\n(15-class supervised)", color=RF_COLOR, edgecolor="black", linewidth=0.4)
    b2 = ax.bar(x, if_vals, width, label="Isolation Forest\n(binary anomaly)", color=IF_COLOR, edgecolor="black", linewidth=0.4)
    b3 = ax.bar(x + width, cnn_vals, width, label="CNN\n(encrypted-traffic sim.)", color=CNN_COLOR, edgecolor="black", linewidth=0.4)
    ax.set_xticks(x)
    ax.set_xticklabels(metric_names)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("Score (0-1)")
    ax.set_title("Shared metric names (not scientifically equivalent tasks)")
    ax.legend(loc="upper right", fontsize=8)
    for group in (b1, b2, b3):
        for bar in group:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.015,
                f"{bar.get_height():.2f}",
                ha="center",
                va="bottom",
                fontsize=7,
            )

    ax = axes[1]
    db_comp_labels = ["Silhouette", "ARI", "NMI", "Noise ratio"]
    db_comp_vals = [
        db_m["silhouette_score"],
        db_m["adjusted_rand_index"],
        db_m["normalized_mutual_info"],
        db_m["noise_ratio"],
    ]
    bars = ax.bar(db_comp_labels, db_comp_vals, color=DB_COLOR, edgecolor="black", linewidth=0.4, width=0.65)
    ax.set_ylim(0, 1.18)
    ax.set_title("DBSCAN clustering metrics (no accuracy stored)")
    ax.set_ylabel("Score")
    annotate_bars(ax, bars, db_comp_vals, as_percent=False)

    fig.suptitle(
        "Model Comparison — different tasks on CICIDS2017; do not rank by accuracy alone",
        fontsize=13,
        fontweight="bold",
        y=1.02,
    )
    savefig(fig, "model_comparison.png")

    print("Done.")


if __name__ == "__main__":
    main()
