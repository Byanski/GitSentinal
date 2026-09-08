import sqlite3
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from app.config import DB_PATH

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Auth session
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_session (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        access_token TEXT NOT NULL,
        username TEXT,
        name TEXT,
        avatar_url TEXT,
        email TEXT,
        auth_type TEXT DEFAULT 'pat',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Scan history
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        status TEXT DEFAULT 'running',
        total_repos INTEGER DEFAULT 0,
        scanned_repos INTEGER DEFAULT 0,
        total_files INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0,
        error_message TEXT
    );
    """)

    # Findings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        repo_name TEXT NOT NULL,
        repo_full_name TEXT NOT NULL,
        branch TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_number INTEGER NOT NULL,
        secret_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        snippet TEXT NOT NULL,
        masked_secret TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE SET NULL
    );
    """)

    # App Settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)

    # Default settings
    default_settings = {
        "daily_scan_enabled": "false",
        "daily_scan_time": "03:00",
        "desktop_notifications": "true",
        "excluded_extensions": ".png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.mp4,.mp3,.pdf,.zip,.tar,.gz,.exe,.bin,.woff,.woff2,.ttf,.eot,.pyc,.lock",
        "excluded_paths": "node_modules,vendor,dist,build,package-lock.json,yarn.lock,pnpm-lock.yaml,Cargo.lock,.git,tests,test,spec,__tests__",
        "min_entropy": "3.2"
    }

    for k, v in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    conn.commit()
    conn.close()

# Auth helpers
def save_auth(access_token: str, username: str = None, name: str = None, avatar_url: str = None, email: str = None, auth_type: str = "pat"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO auth_session (id, access_token, username, name, avatar_url, email, auth_type, updated_at)
    VALUES (1, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
        access_token=excluded.access_token,
        username=excluded.username,
        name=excluded.name,
        avatar_url=excluded.avatar_url,
        email=excluded.email,
        auth_type=excluded.auth_type,
        updated_at=CURRENT_TIMESTAMP;
    """, (access_token, username, name, avatar_url, email, auth_type))
    conn.commit()
    conn.close()

def get_auth() -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT access_token, username, name, avatar_url, email, auth_type, updated_at FROM auth_session WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def clear_auth():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM auth_session WHERE id = 1")
    conn.commit()
    conn.close()

# Settings helpers
def get_all_settings() -> Dict[str, str]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    rows = cursor.fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}

def get_setting(key: str, default: str = "") -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["value"]
    return default

def update_setting(key: str, value: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, value))
    conn.commit()
    conn.close()

# Findings & Scan History helpers
def create_scan_record(total_repos: int = 0) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_history (status, total_repos) VALUES ('running', ?)", (total_repos,))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def update_scan_record(scan_id: int, **kwargs):
    conn = get_db_connection()
    cursor = conn.cursor()
    fields = []
    values = []
    for k, v in kwargs.items():
        fields.append(f"{k} = ?")
        values.append(v)
    values.append(scan_id)
    query = f"UPDATE scan_history SET {', '.join(fields)} WHERE id = ?"
    cursor.execute(query, values)
    conn.commit()
    conn.close()

def save_finding(scan_id: int, repo_name: str, repo_full_name: str, branch: str, file_path: str, line_number: int, secret_type: str, severity: str, snippet: str, masked_secret: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO findings (scan_id, repo_name, repo_full_name, branch, file_path, line_number, secret_type, severity, snippet, masked_secret, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
    """, (scan_id, repo_name, repo_full_name, branch, file_path, line_number, secret_type, severity, snippet, masked_secret))
    conn.commit()
    conn.close()

def get_findings(repo: Optional[str] = None, status: Optional[str] = None, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if repo:
        query += " AND repo_full_name = ?"
        params.append(repo)
    if status and status != "all":
        query += " AND status = ?"
        params.append(status)
    if scan_id:
        query += " AND scan_id = ?"
        params.append(scan_id)
    query += " ORDER BY id DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_finding_status(finding_id: int, status: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
    conn.commit()
    conn.close()

def get_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT repo_full_name) as scanned_repos FROM findings")
    repos_with_findings = cursor.fetchone()["scanned_repos"] or 0
    
    cursor.execute("SELECT COUNT(*) as total_open FROM findings WHERE status = 'open'")
    total_open = cursor.fetchone()["total_open"] or 0
    
    cursor.execute("SELECT COUNT(*) as critical_open FROM findings WHERE status = 'open' AND severity = 'CRITICAL'")
    critical_open = cursor.fetchone()["critical_open"] or 0

    cursor.execute("SELECT COUNT(*) as resolved FROM findings WHERE status = 'resolved'")
    resolved = cursor.fetchone()["resolved"] or 0

    cursor.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT 1")
    latest_scan = cursor.fetchone()

    conn.close()
    return {
        "repos_with_findings": repos_with_findings,
        "total_open": total_open,
        "critical_open": critical_open,
        "resolved": resolved,
        "latest_scan": dict(latest_scan) if latest_scan else None
    }
