from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score
)
from sklearn.model_selection import RepeatedStratifiedKFold


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = PROJECT_ROOT / "datasets" / "synthetic_evaluation.csv"

FEATURE_COLUMNS = [
    "degree",
    "shared_connections",
    "tag_count",
    "malware_indicator",
    "suspicious_activity"
]

RANDOM_STATE = 42
FOLDS = 5
REPEATS = 5


def calculate_metrics(actual, predicted, scores=None):
    actual = np.asarray(actual)
    predicted = np.asarray(predicted)

    tn, fp, fn, tp = confusion_matrix(
        actual, predicted, labels=[0, 1]
    ).ravel()

    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    metrics = {
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": float(
            balanced_accuracy_score(actual, predicted)
        ),
        "precision": float(
            precision_score(actual, predicted, zero_division=0)
        ),
        "recall": float(
            recall_score(actual, predicted, zero_division=0)
        ),
        "specificity": float(specificity),
        "f1_score": float(
            f1_score(actual, predicted, zero_division=0)
        )
    }

    if scores is not None:
        metrics["roc_auc"] = float(
            roc_auc_score(actual, scores)
        )

    return metrics


def summarize_metrics(fold_results, actual, predicted, scores):
    metric_names = list(fold_results[0].keys())

    mean_metrics = {
        metric: round(
            float(np.mean([result[metric] for result in fold_results])),
            4
        )
        for metric in metric_names
    }

    std_metrics = {
        metric: round(
            float(np.std([result[metric] for result in fold_results])),
            4
        )
        for metric in metric_names
    }

    aggregate_metrics = {
        key: round(value, 4)
        for key, value in calculate_metrics(
            actual, predicted, scores
        ).items()
    }

    tn, fp, fn, tp = confusion_matrix(
        actual, predicted, labels=[0, 1]
    ).ravel()

    return {
        **mean_metrics,
        "metric_std": std_metrics,
        "aggregate_metrics": aggregate_metrics,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp)
        }
    }


def run_evaluation():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Evaluation dataset not found: {DATASET_PATH}"
        )

    data = pd.read_csv(DATASET_PATH)

    required_columns = FEATURE_COLUMNS + ["label"]
    missing_columns = [
        column for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Dataset is missing columns: {missing_columns}"
        )

    data = data.dropna(subset=required_columns).copy()

    for column in required_columns:
        data[column] = pd.to_numeric(
            data[column], errors="coerce"
        )

    data = data.dropna(subset=required_columns)

    if data.empty:
        raise ValueError("The evaluation dataset contains no valid records.")

    if not np.isfinite(data[required_columns].to_numpy(dtype=float)).all():
        raise ValueError("The dataset contains non-finite numeric values.")

    if not set(data["label"].unique()).issubset({0, 1}):
        raise ValueError("Labels must use 0 for benign and 1 for malicious.")

    data["label"] = data["label"].astype(int)

    if data["label"].nunique() != 2:
        raise ValueError(
            "Evaluation requires both benign and malicious classes."
        )

    class_counts = data["label"].value_counts()

    if class_counts.min() < FOLDS:
        raise ValueError(
            f"Each class must contain at least {FOLDS} records "
            "for the selected cross-validation method."
        )

    features = data[FEATURE_COLUMNS].astype(float)
    labels = data["label"]

    splitter = RepeatedStratifiedKFold(
        n_splits=FOLDS,
        n_repeats=REPEATS,
        random_state=RANDOM_STATE
    )

    graph_actual = []
    graph_predictions = []
    graph_scores = []
    graph_fold_metrics = []
    feature_importances = []

    baseline_actual = []
    baseline_predictions = []
    baseline_fold_metrics = []

    for train_index, test_index in splitter.split(features, labels):
        X_train = features.iloc[train_index]
        X_test = features.iloc[test_index]
        y_train = labels.iloc[train_index]
        y_test = labels.iloc[test_index]

        model = RandomForestClassifier(
            n_estimators=200,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            min_samples_leaf=1
        )

        model.fit(X_train, y_train)

        predictions = model.predict(X_test)
        probabilities = model.predict_proba(X_test)[:, 1]

        graph_actual.extend(y_test.tolist())
        graph_predictions.extend(predictions.tolist())
        graph_scores.extend(probabilities.tolist())

        graph_fold_metrics.append(
            calculate_metrics(y_test, predictions, probabilities)
        )

        feature_importances.append(model.feature_importances_)

        baseline_predictions_fold = (
            (X_test["degree"] >= 2)
            | (X_test["shared_connections"] >= 2)
            | (X_test["tag_count"] >= 2)
            | (X_test["malware_indicator"] == 1)
            | (X_test["suspicious_activity"] == 1)
        ).astype(int)

        baseline_actual.extend(y_test.tolist())
        baseline_predictions.extend(
            baseline_predictions_fold.tolist()
        )

        baseline_fold_metrics.append(
            calculate_metrics(y_test, baseline_predictions_fold)
        )

    graph_metrics = summarize_metrics(
        graph_fold_metrics,
        graph_actual,
        graph_predictions,
        graph_scores
    )

    baseline_metrics = summarize_metrics(
        baseline_fold_metrics,
        baseline_actual,
        baseline_predictions,
        None
    )

    average_importance = np.mean(feature_importances, axis=0)

    return {
        "evaluation_type": "Synthetic labelled benchmark",
        "dataset": DATASET_PATH.name,
        "total_records": int(len(data)),
        "class_distribution": {
            "benign": int((labels == 0).sum()),
            "malicious": int((labels == 1).sum())
        },
        "training_records": int(
            len(data) - np.ceil(len(data) / FOLDS)
        ),
        "testing_records": int(np.ceil(len(data) / FOLDS)),
        "positive_class": "Malicious",
        "evaluation_method": {
            "method": "Repeated stratified k-fold cross-validation",
            "folds": FOLDS,
            "repeats": REPEATS,
            "total_evaluation_runs": FOLDS * REPEATS,
            "random_state": RANDOM_STATE,
            "description": (
                "Both models are evaluated on identical stratified folds. "
                "Reported primary metrics are averages across folds."
            )
        },
        "models": {
            "graph_based_model": graph_metrics,
            "rule_based_baseline": baseline_metrics
        },
        "feature_importance": {
            feature: round(float(score), 4)
            for feature, score in zip(
                FEATURE_COLUMNS, average_importance
            )
        },
        "limitations": (
            "Results are based on a small synthetic labelled dataset. "
            "The dataset contains deliberately separated benign and "
            "malicious patterns. Cross-validation improves assessment "
            "consistency but does not establish real-world detection "
            "performance or prove that the model generalizes to live "
            "threat intelligence data. Independent real-world labelled "
            "data is required for that conclusion."
        )
    }
