"""Synthetic data generator for RansomWatch machine learning models.

Generates realistic behavioral baseline datasets (normal file system activity)
and synthetic ransomware attack patterns for training and evaluating anomaly detection models.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple
import numpy as np
import pandas as pd

from ml.features import FeatureExtractor

logger = logging.getLogger("ransomwatch.ml.synthetic")


class SyntheticDataGenerator:
    """Generates synthetic baseline and attack telemetry datasets for Isolation Forest training."""

    def __init__(self, random_state: Optional[int] = 42) -> None:
        """Initialize generator with optional random seed for reproducibility.

        Args:
            random_state: Seed for numpy's random generator.
        """
        self.random_state = random_state
        self._feature_names = FeatureExtractor.get_feature_names()

    def generate_normal_activity(
        self,
        num_samples: int = 500,
        random_state: Optional[int] = None,
    ) -> pd.DataFrame:
        """Generate telemetry samples representing benign, everyday file system operations.

        Characteristics:
            - Low modification counts (1-10 per window)
            - Few renames (0-3)
            - Low creation and deletion counts
            - Low operation frequency (typically < 0.5 ops/sec)
            - Low unusual_ext_ratio (0.0 - 0.05)
            - Normal Shannon entropy range (3.0 - 6.0)
            - Zero canary interactions
            - Minimal extension changes

        Args:
            num_samples: Number of observation windows to generate.
            random_state: Optional seed override.

        Returns:
            DataFrame with columns matching FeatureExtractor.get_feature_names().
        """
        if num_samples <= 0:
            return pd.DataFrame(columns=self._feature_names)

        seed = random_state if random_state is not None else self.random_state
        rng = np.random.default_rng(seed)

        # 1. Low modification counts (1-10 per window)
        files_modified = rng.poisson(lam=4.0, size=num_samples).astype(float)
        files_modified = np.clip(files_modified, 1.0, 10.0)

        # 2. Few renames (0-3)
        files_renamed = rng.poisson(lam=0.4, size=num_samples).astype(float)
        files_renamed = np.clip(files_renamed, 0.0, 3.0)

        # 3. Creation and deletion counts
        files_created = rng.poisson(lam=1.5, size=num_samples).astype(float)
        files_created = np.clip(files_created, 0.0, 6.0)

        files_deleted = rng.poisson(lam=0.6, size=num_samples).astype(float)
        files_deleted = np.clip(files_deleted, 0.0, 4.0)

        # 4. Total operations and frequency
        total_operations = files_modified + files_renamed + files_created + files_deleted
        # Assume standard 60-second observation window
        operation_frequency = total_operations / 60.0

        # 5. Low unusual_ext_ratio (0.0 - 0.05, mostly 0.0)
        rare_suspicious = rng.random(size=num_samples) < 0.05
        unusual_ext_ratio = np.where(
            rare_suspicious,
            rng.uniform(0.01, 0.05, size=num_samples),
            0.0,
        )

        # 6. Normal entropy range (3.0 - 6.0)
        avg_entropy = rng.normal(loc=4.5, scale=0.6, size=num_samples)
        avg_entropy = np.clip(avg_entropy, 3.0, 6.0)

        max_entropy = avg_entropy + rng.uniform(0.1, 0.8, size=num_samples)
        max_entropy = np.clip(max_entropy, 3.2, 6.5)

        entropy_std = rng.uniform(0.1, 0.7, size=num_samples)

        # 7. Canary interactions (strictly 0 for normal activity)
        canary_interactions = np.zeros(num_samples, dtype=float)

        # 8. Unique extensions & extension changes
        unique_extensions = rng.integers(1, 5, size=num_samples).astype(float)
        ext_change_count = np.where(
            files_renamed > 0,
            rng.binomial(n=1, p=0.08, size=num_samples),
            0.0,
        ).astype(float)

        data = {
            "files_modified": files_modified,
            "files_renamed": files_renamed,
            "files_created": files_created,
            "files_deleted": files_deleted,
            "total_operations": total_operations,
            "operation_frequency": operation_frequency,
            "unusual_ext_ratio": unusual_ext_ratio,
            "avg_entropy": avg_entropy,
            "max_entropy": max_entropy,
            "entropy_std": entropy_std,
            "canary_interactions": canary_interactions,
            "unique_extensions": unique_extensions,
            "ext_change_count": ext_change_count,
        }

        df = pd.DataFrame(data)[self._feature_names]
        return df

    def generate_ransomware_activity(
        self,
        num_samples: int = 50,
        random_state: Optional[int] = None,
    ) -> pd.DataFrame:
        """Generate telemetry samples representing active ransomware infection patterns.

        Characteristics:
            - High modification counts (50-200 per window)
            - Many renames (20-100) appending ransom extensions
            - High operation frequency (1.5 - 6.0+ ops/sec)
            - High unusual_ext_ratio (0.5 - 1.0)
            - High Shannon entropy (7.0 - 8.0) indicative of strong encryption
            - Possible canary interactions (0 - 5)
            - High extension change counts

        Args:
            num_samples: Number of attack observation windows to generate.
            random_state: Optional seed override.

        Returns:
            DataFrame with columns matching FeatureExtractor.get_feature_names().
        """
        if num_samples <= 0:
            return pd.DataFrame(columns=self._feature_names)

        seed = random_state if random_state is not None else (
            self.random_state + 1000 if self.random_state is not None else None
        )
        rng = np.random.default_rng(seed)

        # 1. High modification counts (50 - 200)
        files_modified = rng.integers(50, 201, size=num_samples).astype(float)

        # 2. Many renames (20 - 100)
        files_renamed = rng.integers(20, 101, size=num_samples).astype(float)

        # 3. Created and deleted files (ransom notes, shadow copy / original deletion)
        files_created = rng.integers(5, 50, size=num_samples).astype(float)
        files_deleted = rng.integers(5, 40, size=num_samples).astype(float)

        # 4. Total operations and high frequency
        total_operations = files_modified + files_renamed + files_created + files_deleted
        operation_frequency = total_operations / 60.0

        # 5. High unusual_ext_ratio (0.5 - 1.0)
        unusual_ext_ratio = rng.uniform(0.5, 1.0, size=num_samples)

        # 6. High Shannon entropy (7.0 - 8.0)
        avg_entropy = rng.uniform(7.05, 7.95, size=num_samples)
        max_entropy = np.clip(avg_entropy + rng.uniform(0.02, 0.05, size=num_samples), 7.1, 8.0)
        entropy_std = rng.uniform(0.02, 0.25, size=num_samples)

        # 7. Possible canary interactions (0 - 5)
        canary_probs = [0.15, 0.35, 0.25, 0.15, 0.07, 0.03]
        canary_interactions = rng.choice([0, 1, 2, 3, 4, 5], size=num_samples, p=canary_probs).astype(float)

        # 8. Unique extensions & extensive extension changes
        unique_extensions = rng.integers(2, 8, size=num_samples).astype(float)
        # Ransomware renames target files to suspicious extensions
        ext_change_count = np.clip(
            files_renamed * rng.uniform(0.7, 1.0, size=num_samples),
            15.0,
            100.0,
        ).astype(float)

        data = {
            "files_modified": files_modified,
            "files_renamed": files_renamed,
            "files_created": files_created,
            "files_deleted": files_deleted,
            "total_operations": total_operations,
            "operation_frequency": operation_frequency,
            "unusual_ext_ratio": unusual_ext_ratio,
            "avg_entropy": avg_entropy,
            "max_entropy": max_entropy,
            "entropy_std": entropy_std,
            "canary_interactions": canary_interactions,
            "unique_extensions": unique_extensions,
            "ext_change_count": ext_change_count,
        }

        df = pd.DataFrame(data)[self._feature_names]
        return df

    def generate_dataset(
        self,
        normal_samples: int = 500,
        anomaly_samples: int = 50,
        random_state: Optional[int] = None,
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """Generate a combined, shuffled telemetry dataset with anomaly labels.

        Labels follow standard scikit-learn IsolationForest conventions:
            1  = Inlier (Normal activity)
            -1 = Outlier (Ransomware anomaly)

        Args:
            normal_samples: Number of normal telemetry windows.
            anomaly_samples: Number of ransomware anomaly windows.
            random_state: Optional seed override.

        Returns:
            Tuple of (X, y) where:
                X: pd.DataFrame with feature columns matching FeatureExtractor.
                y: pd.Series containing int labels (1 or -1).
        """
        seed = random_state if random_state is not None else self.random_state
        rng = np.random.default_rng(seed)

        df_normal = self.generate_normal_activity(
            num_samples=normal_samples,
            random_state=seed,
        )
        labels_normal = pd.Series([1] * len(df_normal), name="label")

        df_anomaly = self.generate_ransomware_activity(
            num_samples=anomaly_samples,
            random_state=seed + 5000 if seed is not None else None,
        )
        labels_anomaly = pd.Series([-1] * len(df_anomaly), name="label")

        # Combine features and labels
        df_combined = pd.concat([df_normal, df_anomaly], ignore_index=True)
        labels_combined = pd.concat([labels_normal, labels_anomaly], ignore_index=True)

        # Shuffle together
        if len(df_combined) > 0:
            indices = np.arange(len(df_combined))
            rng.shuffle(indices)
            df_shuffled = df_combined.iloc[indices].reset_index(drop=True)
            labels_shuffled = labels_combined.iloc[indices].reset_index(drop=True)
        else:
            df_shuffled = df_combined
            labels_shuffled = labels_combined

        logger.info(
            "Generated dataset with %d normal samples and %d anomaly samples (total: %d)",
            normal_samples,
            anomaly_samples,
            len(df_shuffled),
        )

        return df_shuffled, labels_shuffled
