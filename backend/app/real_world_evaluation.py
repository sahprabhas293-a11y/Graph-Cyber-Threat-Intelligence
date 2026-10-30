import json
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier


ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "datasets/real_world/raw/All.csv"
OUTPUT = ROOT / "datasets/real_world/processed"

TARGET = "URL_Type_obf_Type"
RANDOM_STATE = 42
TEST_SIZE = 0.20
CLASSES = ["benign", "defacement", "malware", "phishing", "spam"]


def build_models():
    return {
        "random_forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(
                n_estimators=250,
                max_features="sqrt",
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            )),
        ]),
        "decision_tree": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", DecisionTreeClassifier(
                max_depth=10,
                min_samples_leaf=10,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            )),
        ]),
        "majority_baseline": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", DummyClassifier(strategy="most_frequent")),
        ]),
    }


def multiclass_metrics(model, X_test, y_test):
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)

    result = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
        "macro_precision": float(precision_score(
            y_test, predictions, average="macro", zero_division=0
        )),
        "macro_recall": float(recall_score(
            y_test, predictions, average="macro", zero_division=0
        )),
        "macro_f1": float(f1_score(
            y_test, predictions, average="macro", zero_division=0
        )),
        "weighted_f1": float(f1_score(
            y_test, predictions, average="weighted", zero_division=0
        )),
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=CLASSES
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=CLASSES,
            output_dict=True,
            zero_division=0,
        ),
    }

    try:
        result["roc_auc_ovr_macro"] = float(roc_auc_score(
            y_test,
            probabilities,
            labels=list(model.classes_),
            multi_class="ovr",
            average="macro",
        ))
    except ValueError:
        result["roc_auc_ovr_macro"] = None

    return result, predictions


def binary_metrics(model, X_test, y_test):
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)

    matrix = confusion_matrix(
        y_test, predictions, labels=["benign", "malicious"]
    )
    tn, fp, fn, tp = matrix.ravel()

    malicious_index = list(model.classes_).index("malicious")

    return {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
        "precision": float(precision_score(
            y_test, predictions, pos_label="malicious", zero_division=0
        )),
        "recall": float(recall_score(
            y_test, predictions, pos_label="malicious", zero_division=0
        )),
        "f1": float(f1_score(
            y_test, predictions, pos_label="malicious", zero_division=0
        )),
        "specificity": float(tn / (tn + fp)) if (tn + fp) else None,
        "roc_auc": float(roc_auc_score(
            (y_test == "malicious").astype(int),
            probabilities[:, malicious_index],
        )),
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": ["benign", "malicious"],
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=["benign", "malicious"],
            output_dict=True,
            zero_division=0,
        ),
    }, predictions


def main():
    if not DATASET.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET}")

    OUTPUT.mkdir(parents=True, exist_ok=True)

    print("Loading ISCX-URL2016 dataset...")
    df = pd.read_csv(DATASET, low_memory=False)

    if TARGET not in df.columns:
        raise ValueError(f"Target column {TARGET!r} was not found.")

    original_rows = len(df)

    df = df.loc[:, ~df.columns.astype(str).str.startswith("Unnamed:")].copy()
    df[TARGET] = df[TARGET].astype("string").str.strip().str.lower()
    df = df.dropna(subset=[TARGET])

    unexpected = sorted(set(df[TARGET].unique()) - set(CLASSES))
    if unexpected:
        raise ValueError(f"Unexpected target labels: {unexpected}")

    original_distribution = df[TARGET].value_counts().to_dict()

    feature_columns = [c for c in df.columns if c != TARGET]
    X = df[feature_columns].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    all_missing = X.columns[X.isna().all()].tolist()
    X = X.drop(columns=all_missing)

    constant_columns = [
        c for c in X.columns if X[c].nunique(dropna=True) <= 1
    ]
    X = X.drop(columns=constant_columns)

    if X.empty:
        raise ValueError("No usable numeric feature columns remain.")

    y = df[TARGET].reset_index(drop=True)
    X = X.reset_index(drop=True)

    print("Checking duplicate feature records...")
    feature_hashes = pd.util.hash_pandas_object(
        X, index=False
    ).reset_index(drop=True)

    audit = pd.DataFrame({
        "feature_hash": feature_hashes,
        "label": y,
    })

    conflicting_hashes = set(
        audit.groupby("feature_hash")["label"]
        .nunique()
        .loc[lambda values: values > 1]
        .index
    )

    conflict_mask = feature_hashes.isin(conflicting_hashes)
    conflicting_records_removed = int(conflict_mask.sum())

    valid_mask = ~conflict_mask
    X = X.loc[valid_mask].reset_index(drop=True)
    y = y.loc[valid_mask].reset_index(drop=True)
    feature_hashes = feature_hashes.loc[valid_mask].reset_index(drop=True)

    unique_mask = ~feature_hashes.duplicated()
    duplicate_feature_records_removed = int((~unique_mask).sum())

    X = X.loc[unique_mask].reset_index(drop=True)
    y = y.loc[unique_mask].reset_index(drop=True)

    if y.value_counts().min() < 2:
        raise ValueError("Not enough examples per class for stratified splitting.")

    print("Records before cleaning:", original_rows)
    print("Records after duplicate handling:", len(X))
    print("Conflicting feature patterns removed:", conflicting_records_removed)
    print("Repeated feature records removed:", duplicate_feature_records_removed)
    print("Features used:", len(X.columns))
    print("Removed all-missing features:", all_missing)
    print("Removed constant features:", constant_columns)
    print("\nClass distribution after cleaning:")
    print(y.value_counts().to_string())

    indices = np.arange(len(X))
    train_indices, test_indices = train_test_split(
        indices,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    X_train = X.iloc[train_indices]
    X_test = X.iloc[test_indices]
    y_train = y.iloc[train_indices]
    y_test = y.iloc[test_indices]

    print("\nTraining records:", len(X_train))
    print("Testing records:", len(X_test))

    multiclass_results = {}
    multiclass_predictions = {}

    print("\n========== MULTICLASS EVALUATION ==========")

    for name, model in build_models().items():
        print("Training:", name)
        model.fit(X_train, y_train)

        metrics, predictions = multiclass_metrics(model, X_test, y_test)
        multiclass_results[name] = metrics
        multiclass_predictions[name] = predictions

        print(
            name,
            "| Accuracy:", round(metrics["accuracy"], 4),
            "| Macro F1:", round(metrics["macro_f1"], 4),
            "| Balanced accuracy:", round(metrics["balanced_accuracy"], 4),
        )

    main_model = build_models()["random_forest"]
    main_model.fit(X_train, y_train)

    feature_importances = main_model.named_steps["model"].feature_importances_
    importance_order = np.argsort(feature_importances)[::-1][:15]

    top_features = [
        {
            "feature": str(X.columns[i]),
            "importance": float(feature_importances[i]),
        }
        for i in importance_order
    ]

    print("\n========== BINARY EVALUATION ==========")

    y_binary = y.map(
        lambda label: "benign" if label == "benign" else "malicious"
    )
    y_binary_train = y_binary.iloc[train_indices]
    y_binary_test = y_binary.iloc[test_indices]

    binary_results = {}
    binary_predictions = {}

    for name, model in build_models().items():
        print("Training:", name)
        model.fit(X_train, y_binary_train)

        metrics, predictions = binary_metrics(
            model, X_test, y_binary_test
        )
        binary_results[name] = metrics
        binary_predictions[name] = predictions

        print(
            name,
            "| Accuracy:", round(metrics["accuracy"], 4),
            "| Precision:", round(metrics["precision"], 4),
            "| Recall:", round(metrics["recall"], 4),
            "| F1:", round(metrics["f1"], 4),
            "| Specificity:", round(metrics["specificity"], 4)
            if metrics["specificity"] is not None else "N/A",
            "| ROC-AUC:", round(metrics["roc_auc"], 4),
        )

    prediction_output = pd.DataFrame({
        "actual_multiclass": y_test.to_numpy(),
        "predicted_multiclass": multiclass_predictions["random_forest"],
        "actual_binary": y_binary_test.to_numpy(),
        "predicted_binary": binary_predictions["random_forest"],
    })

    prediction_path = OUTPUT / "iscx_url2016_test_predictions.csv"
    prediction_output.to_csv(prediction_path, index=False)

    results = {
        "experiment": "ISCX-URL2016 real-world URL feature classification",
        "dataset": str(DATASET.relative_to(ROOT)),
        "original_records": original_rows,
        "records_after_cleaning": len(X),
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "feature_count": len(X.columns),
        "target_column": TARGET,
        "original_class_distribution": {
            str(k): int(v) for k, v in original_distribution.items()
        },
        "cleaned_class_distribution": {
            str(k): int(v) for k, v in y.value_counts().items()
        },
        "duplicate_feature_records_removed": duplicate_feature_records_removed,
        "conflicting_feature_patterns_removed": conflicting_records_removed,
        "all_missing_features_removed": all_missing,
        "constant_features_removed": constant_columns,
        "split": {
            "method": "Stratified train/test split",
            "test_size": TEST_SIZE,
            "random_state": RANDOM_STATE,
        },
        "multiclass_results": multiclass_results,
        "binary_results": binary_results,
        "top_random_forest_features": top_features,
        "methodology_limitations": [
            "The source CSV contains engineered URL features but no original URL or domain identifiers.",
            "This experiment evaluates URL-feature classification, not direct graph-based classification.",
            "A direct graph feature comparison cannot be performed for these records without their original identifiers.",
            "The dataset is historical and its results do not establish current threat prevalence.",
            "Exact duplicate feature vectors were removed before splitting to reduce train/test leakage.",
            "Conflicting labels for identical feature vectors were excluded.",
            "No handcrafted rule-based baseline is claimed because the original URL strings are unavailable.",
            "The decision tree is an interpretable learned baseline, not a handcrafted rule-based system.",
        ],
        "prediction_file": str(prediction_path.relative_to(ROOT)),
    }

    result_path = OUTPUT / "iscx_url2016_evaluation.json"
    with result_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, allow_nan=False)

    print("\n========== TOP FEATURES ==========")
    for item in top_features:
        print(item["feature"], round(item["importance"], 5))

    print("\n========== OUTPUT FILES ==========")
    print(result_path)
    print(prediction_path)
    print("\nReal-world URL evaluation completed.")
    print("Existing synthetic evaluation and Neo4j data were not modified.")


if __name__ == "__main__":
    main()
