"""Machine learning anomaly detection model for RansomWatch.

Implements Isolation Forest unsupervised learning for detecting ransomware-like
patterns in filesystem event metrics, with model persistence, telemetry scoring,
and explainability features.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from config import Config
from database.db import DatabaseManager
from ml.features import FeatureExtractor
from ml.synthetic_data import SyntheticDataGenerator

logger = logging.getLogger("ransomwatch.ml.model")


class AnomalyDetector:
    """Unsupervised Isolation Forest anomaly detector for ransomware behavior telemetry."""

    def __init__(self, config: Optional[Any] = None) -> None:
        """Initialize AnomalyDetector with configuration.

        Args:
            config: Optional Config instance or class. If omitted, uses global configuration.
        """
        if config is None:
            try:
                from config import config as default_config  # type: ignore
                self.config = default_config
            except Exception:
                self.config = Config()
        elif isinstance(config, type):
            self.config = config()
        else:
            self.config = config

        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False
        self.feature_extractor: FeatureExtractor = FeatureExtractor()

        raw_path = getattr(self.config, "MODEL_PATH", Path("ml/trained_model/isolation_forest.joblib"))
        self.model_path: Path = Path(raw_path)
        self.training_metadata: Dict[str, Any] = {}

        # Auto-create directory structure and attempt to load existing model
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            if self.model_path.is_file():
                self.load_model()
        except Exception as exc:
            logger.debug("Automatic initial model loading skipped or failed: %s", exc)

    def train(
        self,
        training_data: pd.DataFrame,
        contamination: float = 0.1,
    ) -> Dict[str, Any]:
        """Train an Isolation Forest model on observation windows.

        Args:
            training_data: pandas DataFrame containing training features.
            contamination: Expected proportion of outliers in the data (0.0 to 0.5).

        Returns:
            Dictionary summary containing training statistics.

        Raises:
            ValueError: If training_data is empty or not a DataFrame.
        """
        if training_data is None or not isinstance(training_data, pd.DataFrame) or training_data.empty:
            raise ValueError("Training data must be a non-empty pandas DataFrame.")

        feature_names = self.feature_extractor.get_feature_names()

        # Ensure all required feature columns exist, filling missing ones with 0.0
        data_clean = training_data.copy()
        for col in feature_names:
            if col not in data_clean.columns:
                data_clean[col] = 0.0

        # Handle missing and infinite values
        data_features = data_clean[feature_names].fillna(0.0).replace([np.inf, -np.inf], 0.0)

        # Validate contamination range
        contamination_val = float(max(0.001, min(0.5, contamination)))

        logger.info(
            "Training IsolationForest on %d samples with contamination=%.3f",
            len(data_features),
            contamination_val,
        )

        model = IsolationForest(
            contamination=contamination_val,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(data_features)

        # Persist model artifact
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, str(self.model_path))

        now_iso = datetime.now(timezone.utc).isoformat()
        summary: Dict[str, Any] = {
            "status": "success",
            "num_samples": int(len(data_features)),
            "timestamp": now_iso,
            "features": feature_names,
            "contamination": contamination_val,
            "model_path": str(self.model_path),
        }

        self.model = model
        self.is_trained = True
        self.training_metadata = summary

        # Log training execution to database
        try:
            db = DatabaseManager()
            db.insert_training_log({
                "timestamp": now_iso,
                "num_samples": int(len(data_features)),
                "features_used": feature_names,
                "contamination_param": contamination_val,
                "model_path": str(self.model_path),
                "notes": f"Trained IsolationForest with {len(data_features)} observation samples.",
            })
            db.close()
        except Exception as exc:
            logger.warning("Could not persist ML training log to database: %s", exc)

        logger.info("Isolation Forest successfully trained and saved to %s", self.model_path)
        return summary

    def load_model(self) -> bool:
        """Load saved model artifact from disk.

        Returns:
            True if model was successfully loaded, False otherwise.
        """
        if not self.model_path.exists():
            logger.warning("Model file not found at %s", self.model_path)
            return False

        try:
            loaded_model = joblib.load(str(self.model_path))
            if not isinstance(loaded_model, IsolationForest):
                logger.error("Loaded artifact at %s is not an IsolationForest instance.", self.model_path)
                return False

            self.model = loaded_model
            self.is_trained = True
            logger.info("Successfully loaded IsolationForest model from %s", self.model_path)
            return True
        except Exception as exc:
            logger.error("Failed to load model from %s: %s", self.model_path, exc)
            self.model = None
            self.is_trained = False
            return False

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Predict whether a given feature dictionary indicates anomalous ransomware behavior.

        Args:
            features: Dictionary containing file operation metrics.

        Returns:
            Dictionary with prediction results:
                - is_anomaly: bool (True if anomalous, False otherwise)
                - anomaly_score: float (decision_function value, negative indicates anomaly)
                - prediction: int (1 for normal, -1 for anomaly)
                - contributing_factors: List of descriptive reasons for anomaly detection
        """
        if not self.is_trained or self.model is None:
            return {
                "error": "Model not trained",
                "is_anomaly": None,
                "anomaly_score": None,
            }

        # Sanitize and extract features
        validated = self.feature_extractor.validate_features(features)
        feature_names = self.feature_extractor.get_feature_names()
        feature_df = pd.DataFrame([[validated[name] for name in feature_names]], columns=feature_names)

        # Model evaluation: decision_function < 0 indicates anomaly in scikit-learn IsolationForest
        score = float(self.model.decision_function(feature_df)[0])
        pred = int(self.model.predict(feature_df)[0])
        is_anomaly = bool(pred == -1)

        contributing_factors = self._identify_contributing_factors(validated)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": score,
            "prediction": pred,
            "contributing_factors": contributing_factors,
        }

    def _identify_contributing_factors(self, features: Dict[str, float]) -> List[str]:
        """Identify which features deviate from typical normal ranges to provide explainability.

        Args:
            features: Validated feature dictionary.

        Returns:
            List of human-readable factor descriptions explaining the anomalous indicators.
        """
        factors: List[str] = []

        files_modified = features.get("files_modified", 0.0)
        if files_modified > 25.0:
            factors.append(f"Elevated file modifications ({int(files_modified)} modified, baseline: <=10)")

        files_renamed = features.get("files_renamed", 0.0)
        if files_renamed > 5.0:
            factors.append(f"High rename/move frequency ({int(files_renamed)} files renamed, baseline: <=3)")

        unusual_ext_ratio = features.get("unusual_ext_ratio", 0.0)
        if unusual_ext_ratio > 0.05:
            factors.append(f"Suspicious ransomware extension ratio ({unusual_ext_ratio:.1%}, baseline: <5%)")

        avg_entropy = features.get("avg_entropy", 0.0)
        if avg_entropy > 6.8:
            factors.append(f"High average Shannon entropy indicative of encryption ({avg_entropy:.2f}, baseline: 3.0-6.0)")

        max_entropy = features.get("max_entropy", 0.0)
        if max_entropy >= 7.5:
            factors.append(f"Peak file entropy indicates encrypted ciphertext ({max_entropy:.2f} >= 7.5)")

        canary_interactions = features.get("canary_interactions", 0.0)
        if canary_interactions > 0.0:
            factors.append(f"Decoy canary file access detected ({int(canary_interactions)} interaction(s))")

        ext_change_count = features.get("ext_change_count", 0.0)
        if ext_change_count > 3.0:
            factors.append(f"Frequent file extension modifications ({int(ext_change_count)} changes observed)")

        operation_frequency = features.get("operation_frequency", 0.0)
        if operation_frequency > 2.0:
            factors.append(f"Rapid burst filesystem activity ({operation_frequency:.2f} ops/sec, baseline: <0.5)")

        total_operations = features.get("total_operations", 0.0)
        if total_operations > 50.0:
            factors.append(f"Abnormal total operation volume ({int(total_operations)} events in window)")

        return factors

    def retrain_with_new_data(self, new_normal_data: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        """Append newly observed benign data to training baseline and retrain the model.

        If new_normal_data is None or empty, attempts to retrieve normal observation
        windows recorded in the SQLite database.

        Args:
            new_normal_data: Optional DataFrame containing additional normal telemetry samples.

        Returns:
            Dictionary summary of the retraining execution.
        """
        generator = SyntheticDataGenerator()
        baseline = generator.generate_normal_activity(num_samples=500)

        additional_dfs: List[pd.DataFrame] = []

        # Check provided dataframe
        if new_normal_data is not None and isinstance(new_normal_data, pd.DataFrame) and not new_normal_data.empty:
            additional_dfs.append(new_normal_data)

        # Retrieve benign detection windows from database if available
        try:
            db = DatabaseManager()
            windows = db.get_detection_windows(limit=500, only_anomalies=False)
            db.close()
            if windows:
                records: List[Dict[str, float]] = []
                for w in windows:
                    # w is DetectionWindow model
                    if not getattr(w, "is_anomaly", False):
                        records.append({
                            "files_modified": float(getattr(w, "modifications", 0)),
                            "files_renamed": float(getattr(w, "renames", 0)),
                            "files_created": float(getattr(w, "creations", 0)),
                            "files_deleted": float(getattr(w, "deletions", 0)),
                            "total_operations": float(getattr(w, "total_events", 0)),
                            "operation_frequency": float(getattr(w, "total_events", 0)) / 60.0,
                            "unusual_ext_ratio": float(getattr(w, "unusual_ext_ratio", 0.0)),
                            "avg_entropy": float(getattr(w, "avg_entropy", 0.0)),
                            "max_entropy": float(getattr(w, "avg_entropy", 0.0)),
                            "entropy_std": 0.2,
                            "canary_interactions": float(getattr(w, "canary_hits", 0)),
                            "unique_extensions": 2.0,
                            "ext_change_count": 0.0,
                        })
                if records:
                    df_db = pd.DataFrame(records)
                    additional_dfs.append(df_db)
                    logger.info("Incorporated %d benign detection windows from database.", len(records))
        except Exception as exc:
            logger.debug("Could not incorporate database detection windows for retraining: %s", exc)

        if additional_dfs:
            combined = pd.concat([baseline] + additional_dfs, ignore_index=True)
        else:
            combined = baseline

        logger.info("Retraining anomaly detector with %d total samples", len(combined))
        return self.train(combined, contamination=0.05)

    def get_model_info(self) -> Dict[str, Any]:
        """Return operational status and metadata for the current model.

        Returns:
            Dictionary with training status, model artifact path, hyperparameters, and feature list.
        """
        params = None
        if self.model is not None:
            params = {
                "n_estimators": getattr(self.model, "n_estimators", None),
                "contamination": getattr(self.model, "contamination", None),
                "random_state": getattr(self.model, "random_state", None),
                "max_samples": getattr(self.model, "max_samples_", None),
                "n_features_in": getattr(self.model, "n_features_in_", None),
            }

        return {
            "is_trained": self.is_trained,
            "model_path": str(self.model_path),
            "model_exists": self.model_path.exists(),
            "features": self.feature_extractor.get_feature_names(),
            "parameters": params,
            "timestamp": self.training_metadata.get("timestamp"),
            "num_samples": self.training_metadata.get("num_samples"),
            "contamination": self.training_metadata.get("contamination"),
        }

    def generate_and_train_default(
        self,
        num_normal: int = 500,
        contamination: float = 0.05,
    ) -> Dict[str, Any]:
        """Convenience method for initial setup: synthesizes normal telemetry and trains model.

        Args:
            num_normal: Number of synthetic normal observation windows to generate.
            contamination: Expected anomaly contamination rate for training.

        Returns:
            Dictionary summary of the training run.
        """
        logger.info("Synthesizing %d normal telemetry samples for default baseline...", num_normal)
        generator = SyntheticDataGenerator()
        training_df = generator.generate_normal_activity(num_samples=num_normal)
        return self.train(training_df, contamination=contamination)
