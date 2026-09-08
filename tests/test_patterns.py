import pytest
from app.scanner.patterns import (
    scan_line_for_secrets,
    calculate_shannon_entropy,
    mask_secret,
    is_false_positive
)

def test_entropy_calculation():
    # Repetitive string has low entropy
    low_entropy = calculate_shannon_entropy("aaaaaaaaaaaa")
    assert low_entropy == 0.0

    # High randomness string has high entropy
    high_entropy = calculate_shannon_entropy("a8B!d9#Z1$qL0@")
    assert high_entropy > 3.0

def test_mask_secret():
    secret = "sk-proj-1234567890abcdef1234567890abcdef"
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
    assert is_false_positive("AKIAIOSFODNN7EXAMPLE") is False

def test_detect_aws_access_key():
    line = 'aws_access_key = "AKIAIOSFODNN7EXAMPLE"'
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "aws_access_key" for d in detections)
    assert any(d["severity"] == "CRITICAL" for d in detections)

def test_detect_openai_key():
    line = 'export OPENAI_API_KEY="sk-proj-abc123DEF456ghi789JKL012mno345PQR678stu901VWX234"'
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "openai_api_key" for d in detections)

def test_detect_github_pat():
    line = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";'
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "github_pat" for d in detections)

def test_detect_database_url():
    line = 'DATABASE_URL=postgres://appuser:SecretPassword99@db.prod.internal:5432/production'
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "database_url_credentials" for d in detections)

def test_detect_private_key():
    line = '-----BEGIN RSA PRIVATE KEY-----'
    detections = scan_line_for_secrets(line)
    assert len(detections) >= 1
    assert any(d["rule_id"] == "private_key" for d in detections)

def test_detect_generic_secret():
    line = 'API_KEY = "x7K9pLm2Qv5Wz8Rt3N6sB1jC"'
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
