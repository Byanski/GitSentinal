import pytest
import sqlite3
from app.database import (
    init_db,
    save_auth,
    get_auth,
    clear_auth,
    get_all_settings,
    update_setting,
    save_finding,
    get_findings,
    update_finding_status,
    get_stats
)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_auth_persistence():
    clear_auth()
    assert get_auth() is None

    save_auth(
        access_token="ghp_test1234567890",
        username="octocat",
        name="Mona Lisa Octocat",
        avatar_url="https://github.com/images/octocat.png",
        email="octocat@github.com",
        auth_type="pat"
    )

    auth = get_auth()
    assert auth is not None
    assert auth["username"] == "octocat"
    assert auth["access_token"] == "ghp_test1234567890"

    clear_auth()
    assert get_auth() is None

def test_settings_persistence():
    update_setting("daily_scan_enabled", "true")
    update_setting("daily_scan_time", "04:30")

    settings = get_all_settings()
    assert settings.get("daily_scan_enabled") == "true"
    assert settings.get("daily_scan_time") == "04:30"

def test_findings_and_stats():
    save_finding(
        scan_id=1,
        repo_name="my-repo",
        repo_full_name="octocat/my-repo",
        branch="main",
        file_path="src/config.py",
        line_number=42,
        secret_type="OpenAI API Key",
        severity="CRITICAL",
        snippet='OPENAI_KEY = "sk-proj-..."',
        masked_secret="sk-p****cdef"
    )

    findings = get_findings(repo="octocat/my-repo")
    assert len(findings) >= 1
    f = findings[0]
    assert f["repo_name"] == "my-repo"
    assert f["line_number"] == 42
    assert f["status"] == "open"

    update_finding_status(f["id"], "resolved")
    resolved_findings = get_findings(status="resolved")
    assert any(rf["id"] == f["id"] for rf in resolved_findings)

    stats = get_stats()
    assert "total_open" in stats
    assert "critical_open" in stats
    assert "resolved" in stats
