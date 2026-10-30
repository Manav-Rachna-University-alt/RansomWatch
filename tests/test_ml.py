"""Unit and integration tests for RansomWatch machine learning modules."""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from config import Config, config
from ml.features import FeatureExtractor, FEATURE_NAMES
from ml.synthetic_data import SyntheticDataGenerator
from ml.model import AnomalyDetector


def test_feature_names_integrity():
    """Verify that feature names are consistent and match specifications."""
    extractor = FeatureExtractor()
    feature_names = extractor.get_feature_names()
    assert feature_names == FEATURE_NAMES
    assert len(feature_names) == 13
    assert "files_modified" in feature_names
    assert "avg_entropy" in feature_names
    assert "canary_interactions" in feature_names
    assert "unusual_ext_ratio" in feature_names


def test_extract_features_empty():
    """Test feature extraction on empty event list."""
    extractor = FeatureExtractor()
    features = extractor.extract_features([])
    assert isinstance(features, dict)
    for name in FEATURE_NAMES:
        assert features[name] == 0.0


def test_extract_features_activity():
    """Test feature extraction on simulated file events."""
    extractor = FeatureExtractor()
    events = [
        {"event_type": "modified", "file_path": "C:/docs/report.docx", "entropy": 4.5, "is_canary": False},
        {"event_type": "modified", "file_path": "C:/docs/data.xlsx", "entropy": 5.0, "is_canary": False},
        {"event_type": "moved", "file_path": "C:/docs/test.txt", "old_extension": ".txt", "extension": ".locked", "entropy": 7.8, "is_canary": False},
        {"event_type": "deleted", "file_path": "C:/docs/canary_decoy.txt", "is_canary": True, "entropy": -1.0},
        {"event_type": "created", "file_path": "C:/docs/ransom_note.txt", "entropy": 3.2, "is_canary": False},
    ]
    features = extractor.extract_features(events, window_seconds=60.0)

    assert features["files_modified"] == 2.0
    assert features["files_renamed"] == 1.0
    assert features["files_created"] == 1.0
    assert features["files_deleted"] == 1.0
    assert features["total_operations"] == 5.0
    assert features["operation_frequency"] == pytest.approx(5.0 / 60.0)
    assert features["canary_interactions"] == 1.0
    assert features["ext_change_count"] == 1.0
    assert features["unusual_ext_ratio"] == pytest.approx(1.0 / 5.0)

    # Entropies considered: 4.5, 5.0, 7.8, 3.2 (-1.0 skipped)
    expected_avg = (4.5 + 5.0 + 7.8 + 3.2) / 4.0
    assert features["avg_entropy"] == pytest.approx(expected_avg)
    assert features["max_entropy"] == pytest.approx(7.8)


def test_validate_and_to_array():
    """Test feature validation and numpy array conversion."""
    extractor = FeatureExtractor()
    bad_features = {
        "files_modified": -5,
        "avg_entropy": 12.0,
        "unusual_ext_ratio": None,
        "operation_frequency": float("nan"),
    }
    validated = extractor.validate_features(bad_features)
    assert validated["files_modified"] == 0.0
    assert validated["avg_entropy"] == 8.0
    assert validated["unusual_ext_ratio"] == 0.0
    assert validated["operation_frequency"] == 0.0

    arr = extractor.features_to_array(validated)
    assert isinstance(arr, np.ndarray)
    assert arr.shape == (len(FEATURE_NAMES),)
    assert not np.isnan(arr).any()


def test_synthetic_data_generator():
    """Test generating normal and ransomware datasets."""
    generator = SyntheticDataGenerator(random_state=42)

    df_normal = generator.generate_normal_activity(num_samples=100)
    assert len(df_normal) == 100
    assert list(df_normal.columns) == FEATURE_NAMES
    assert (df_normal["canary_interactions"] == 0.0).all()
    assert (df_normal["unusual_ext_ratio"] <= 0.06).all()
    assert (df_normal["avg_entropy"] >= 3.0).all()
    assert (df_normal["avg_entropy"] <= 6.0).all()

    df_attack = generator.generate_ransomware_activity(num_samples=25)
    assert len(df_attack) == 25
    assert (df_attack["files_modified"] >= 50.0).all()
    assert (df_attack["avg_entropy"] >= 7.0).all()
    assert (df_attack["unusual_ext_ratio"] >= 0.5).all()

    X, y = generator.generate_dataset(normal_samples=100, anomaly_samples=20)
    assert len(X) == 120
    assert len(y) == 120
    assert (y == 1).sum() == 100
    assert (y == -1).sum() == 20


def test_anomaly_detector_lifecycle(tmp_path):
    """Test AnomalyDetector training, persistence, and prediction."""
    class CustomConfig:
        MODEL_PATH = tmp_path / "test_model.joblib"
        TIME_WINDOW_SECONDS = 60

    detector = AnomalyDetector(config=CustomConfig())
    assert not detector.is_trained

    # Predict before training returns error
    pred_unfit = detector.predict({"files_modified": 1})
    assert "error" in pred_unfit
    assert pred_unfit["is_anomaly"] is None

    # Train default model
    summary = detector.generate_and_train_default(num_normal=100, contamination=0.05)
    assert summary["status"] == "success"
    assert detector.is_trained
    assert Path(CustomConfig.MODEL_PATH).exists()

    # Normal activity prediction
    normal_features = {
        "files_modified": 3.0,
        "files_renamed": 0.0,
        "files_created": 1.0,
        "files_deleted": 0.0,
        "total_operations": 4.0,
        "operation_frequency": 4.0 / 60.0,
        "unusual_ext_ratio": 0.0,
        "avg_entropy": 4.2,
        "max_entropy": 4.5,
        "entropy_std": 0.2,
        "canary_interactions": 0.0,
        "unique_extensions": 2.0,
        "ext_change_count": 0.0,
    }
    pred_normal = detector.predict(normal_features)
    assert "prediction" in pred_normal
    assert pred_normal["prediction"] == 1
    assert pred_normal["is_anomaly"] is False
    assert len(pred_normal["contributing_factors"]) == 0

    # Ransomware activity prediction
    attack_features = {
        "files_modified": 150.0,
        "files_renamed": 80.0,
        "files_created": 20.0,
        "files_deleted": 15.0,
        "total_operations": 265.0,
        "operation_frequency": 265.0 / 60.0,
        "unusual_ext_ratio": 0.95,
        "avg_entropy": 7.9,
        "max_entropy": 7.98,
        "entropy_std": 0.05,
        "canary_interactions": 3.0,
        "unique_extensions": 5.0,
        "ext_change_count": 75.0,
    }
    pred_attack = detector.predict(attack_features)
    assert pred_attack["prediction"] == -1
    assert pred_attack["is_anomaly"] is True
    assert len(pred_attack["contributing_factors"]) > 0

    # Load model in new instance
    detector2 = AnomalyDetector(config=CustomConfig())
    assert detector2.is_trained
    info = detector2.get_model_info()
    assert info["is_trained"] is True
    assert info["model_exists"] is True

    # Retrain with additional data
    generator = SyntheticDataGenerator()
    new_data = generator.generate_normal_activity(num_samples=20)
    retrain_summary = detector2.retrain_with_new_data(new_data)
    assert retrain_summary["status"] == "success"
