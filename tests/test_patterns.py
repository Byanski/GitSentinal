import pytest
import base64
from app.scanner.patterns import (
    scan_line_for_secrets,
    calculate_shannon_entropy,
    mask_secret,
    is_false_positive
)

def _d(b64_str: str) -> str:
    """Decode test fixture at runtime so raw credentials don't appear in repository source code."""
    return base64.b64decode(b64_str.encode()).decode()

def test_entropy_calculation():
    # Repetitive string has low entropy
    low_entropy = calculate_shannon_entropy("aaaaaaaaaaaa")
    assert low_entropy == 0.0

    # High randomness string has high entropy
    high_entropy = calculate_shannon_entropy("a8B!d9#Z1$qL0@")
    assert high_entropy > 3.0

def test_mask_secret():
    # Decoded at runtime: mock test secret
    secret = _d("c2stcHJvai0xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZg==")
    masked = mask_secret(secret)
    assert masked.startswith("sk-p")
    assert masked.endswith("cdef")
    assert "****" in masked

def test_false_positive_filter():
    assert is_false_positive("your_api_key_here") is True
    assert is_false_positive("PLACEHOLDER_TOKEN") is True
    assert is_false_positive("sk_test_123456789") is True
    assert is_false_positive("1111111111111111") is True
    assert is_false_positive("${ENV_API_KEY}") is True
    # Decoded at runtime: AWS mock documentation key
    assert is_false_positive(_d("QUtJQUlPU0ZPRE5ON0VYQU1QTEU=")) is False

def test_detect_aws_access_key():
    line = _d("YXdzX2FjY2Vzc19rZXkgPSAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUi")
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "aws_access_key" for d in detections)
    assert any(d["severity"] == "CRITICAL" for d in detections)

def test_detect_openai_key():
    line = _d("ZXhwb3J0IE9QRU5BSV9BUElfS0VZPSJzay1wcm9qLWFiYzEyM0RFRjQ1NmdoaTc4OUpLTDAxMm1ubzM0NVBRUjY3OHN0dTkwMVZXWDIzNCI=")
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "openai_api_key" for d in detections)

def test_detect_github_pat():
    line = _d("Y29uc3QgdG9rZW4gPSAiZ2hwXzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiI7")
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "github_pat" for d in detections)

def test_detect_database_url():
    line = _d("REFUQUJBU0VfVVJMPXBvc3RncmVzOi8vYXBwdXNlcjpTZWNyZXRQYXNzd29yZDk5QGRiLnByb2QuaW50ZXJuYWw6NTQzMi9wcm9kdWN0aW9u")
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "database_url_credentials" for d in detections)

def test_detect_private_key():
    line = _d("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==")
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "private_key" for d in detections)

def test_detect_generic_secret():
    line = _d("QVBJX0tFWSA9ICJ4N0s5cExtMlF2NVd6OFJ0M042c0IxakMi")
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "generic_secret_assignment" for d in detections)

def test_ignore_clean_code():
    clean_lines = [
        'import os',
        'print("Hello world")',
        'const port = 8080;',
        '# TODO: Add your API key here',
        'path = os.getenv("API_KEY")'
    ]
    for line in clean_lines:
        detections = scan_line_for_secrets(line)
        assert len(detections) == 0, f"Expected 0 detections for: {line}"
