from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = PROJECT_ROOT / "datasets" / "synthetic_evaluation.csv"


FEATURE_COLUMNS = [
    "degree",
    "shared_connections",
    "tag_count",
    "malware_indicator",
    "suspicious_activity"
]


def calculate_metrics(actual, predicted):
    return {
        "accuracy": round(
            accuracy_score(actual, predicted), 4
        ),
        "precision": round(
            precision_score(actual, predicted, zero_division=0), 4
        ),
        "recall": round(
            recall_score(actual, predicted, zero_division=0), 4
        ),
        "f1_score": round(
            f1_score(actual, predicted, zero_division=0), 4
        )
    }


def run_evaluation():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Evaluation dataset not found: {DATASET_PATH}"
        )

    data = pd.read_csv(DATASET_PATH)

    required_columns = FEATURE_COLUMNS + ["label"]

    missing_columns = [
        column
        for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Dataset is missing columns: {missing_columns}"
        )

    data = data.dropna(subset=required_columns)

    if data["label"].nunique() != 2:
        raise ValueError(
            "Evaluation requires two classes: benign and malicious."
        )

    if data["label"].value_counts().min() < 2:
        raise ValueError(
            "Each class must contain at least two records."
        )

    features = data[FEATURE_COLUMNS]
    labels = data["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    graph_predictions = model.predict(X_test)

    graph_metrics = calculate_metrics(
        y_test,
        graph_predictions
    )

    rule_predictions = (
        (X_test["degree"] >= 2)
        | (X_test["shared_connections"] >= 2)
        | (X_test["tag_count"] >= 2)
        | (X_test["malware_indicator"] == 1)
        | (X_test["suspicious_activity"] == 1)
    ).astype(int)

    baseline_metrics = calculate_metrics(
        y_test,
        rule_predictions
    )

    return {
        "evaluation_type": "Synthetic labelled benchmark",
        "dataset": DATASET_PATH.name,
        "total_records": int(len(data)),
        "training_records": int(len(X_train)),
        "testing_records": int(len(X_test)),
        "positive_class": "Malicious",
        "models": {
            "graph_based_model": graph_metrics,
            "rule_based_baseline": baseline_metrics
        },
        "feature_importance": {
            feature: round(float(score), 4)
            for feature, score in zip(
                FEATURE_COLUMNS,
                model.feature_importances_
            )
        },
        "limitations": (
            "Results are based on a synthetic labelled dataset. "
            "They demonstrate the evaluation workflow and do not "
            "establish real-world detection performance."
        )
    }
