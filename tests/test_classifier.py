"""
tests/test_classifier.py — Pytest suite for ClassifierService.
"""

import sys
import time

import pytest

sys.path.insert(0, ".")  # ensure project root is on path

from classifier.classifier_service import ClassificationResult, ClassifierService


@pytest.fixture(scope="module")
def service():
    """Load ClassifierService once for all tests in this module."""
    return ClassifierService()


def test_result_has_all_fields(service):
    """
    TEST 1:
    - calls service.predict() with an all-zero alert dict
    - asserts result is a ClassificationResult instance
    - asserts all 5 fields exist
    - asserts len(result.top_features) == 3
    - asserts result.alert_id == the value passed in
    """
    alert_id_value = "ALT-TEST-001"
    alert = {"alert_id": alert_id_value, "severity_raw": 0.0}

    result = service.predict(alert)

    assert isinstance(result, ClassificationResult)
    assert hasattr(result, "alert_id")
    assert hasattr(result, "severity")
    assert hasattr(result, "confidence")
    assert hasattr(result, "top_features")
    assert hasattr(result, "timestamp")

    assert result.alert_id == alert_id_value
    assert len(result.top_features) == 3


def test_severity_is_valid_tier(service):
    """
    TEST 2:
    - calls service.predict() with all-max-value features
    - asserts result.severity is one of the 5 valid tiers
    - asserts 0.0 <= result.confidence <= 1.0
    """
    # Simulate high attack signal based on BETH fields 
    # (severity_raw is typically highly indicative of attacks when high)
    max_alert = {
        "alert_id": "ALT-MAX",
        "severity_raw": 99.0,
        "event_type": "execve",
        "processName": "bash",
    }

    result = service.predict(max_alert)

    valid_tiers = {"BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result.severity in valid_tiers
    assert 0.0 <= result.confidence <= 1.0


def test_predict_runs_under_100ms(service):
    """
    TEST 3:
    - uses time.perf_counter() to time a single predict() call
    - asserts elapsed_ms < 100
    - prints the actual elapsed time
    """
    alert = {
        "alert_id": "ALT-SPEED",
        "severity_raw": 1.0,
        "event_type": "read",
        "processName": "python",
    }

    t0 = time.perf_counter()
    _ = service.predict(alert)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print(f"\n[Test] predict() executed in {elapsed_ms:.2f} ms")
    assert elapsed_ms < 100
