"""Shannon entropy calculation utility for ransomware detection.

Ransomware encrypts files using symmetric algorithms (AES, ChaCha20, etc.),
producing ciphertext with near-maximum theoretical information entropy (~8.0 bits/byte).
Measuring file entropy allows rapid discrimination between plaintext and encrypted content.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from pathlib import Path
from typing import Union

logger = logging.getLogger("ransomwatch.monitoring.entropy")


def calculate_data_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of raw bytes.

    Shannon entropy H(X) = - sum(p(x) * log2(p(x))) for each unique byte value.
    The resulting value is in the range [0.0, 8.0] bits per byte.

    Args:
        data: Raw byte sequence to analyze.

    Returns:
        Shannon entropy as a float between 0.0 and 8.0. Returns 0.0 for empty data.
    """
    if not data:
        return 0.0

    length = len(data)
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def calculate_file_entropy(file_path: Union[str, Path], chunk_size: int = 65536) -> float:
    """Calculate the Shannon entropy of a file on disk using streaming chunk reads.

    Processes files in chunks to avoid high memory overhead on large files.
    Gracefully handles locked, missing, or unreadable files.

    Args:
        file_path: Path to the target file.
        chunk_size: Size of byte chunks read iteratively (default 64KB).

    Returns:
        Shannon entropy as a float between 0.0 and 8.0.
        Returns 0.0 for empty files.
        Returns -1.0 if the file cannot be accessed, read, or does not exist.
    """
    path = Path(file_path)
    try:
        if not path.exists() or not path.is_file():
            logger.debug("Cannot calculate entropy: %s does not exist or is not a regular file", file_path)
            return -1.0

        byte_counts = [0] * 256
        total_bytes = 0

        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                for byte in chunk:
                    byte_counts[byte] += 1

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    except (PermissionError, FileNotFoundError, IsADirectoryError, OSError) as err:
        logger.warning("Unreadable file for entropy calculation '%s': %s", file_path, err)
        return -1.0
    except Exception as exc:
        logger.error("Unexpected error calculating entropy for '%s': %s", file_path, exc)
        return -1.0


def is_high_entropy(entropy: float, threshold: float = 7.0) -> bool:
    """Determine whether an entropy value exceeds the suspicious encryption threshold.

    Typical plain text, code, and office documents have entropy between 2.0 and 5.5.
    Encrypted files or heavily compressed archives (zip, rar) generally exceed 7.0.

    Args:
        entropy: Calculated Shannon entropy value.
        threshold: Minimum entropy threshold to flag (default 7.0).

    Returns:
        True if entropy is at or above the threshold and non-negative, False otherwise.
    """
    if entropy < 0.0:
        return False
    return entropy >= threshold
