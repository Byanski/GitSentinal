import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    # Running inside a PyInstaller frozen binary
    BASE_DIR = Path(sys._MEIPASS)
    DATA_DIR = Path.cwd() / "data"
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_DIR = BASE_DIR / "data"

APP_DIR = BASE_DIR / "app"
STATIC_DIR = APP_DIR / "static"
if not STATIC_DIR.exists() and (BASE_DIR / "static").exists():
    STATIC_DIR = BASE_DIR / "static"

DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "gitsentinel.db"

HOST = os.getenv("GITSENTINEL_HOST", "127.0.0.1")
PORT = int(os.getenv("GITSENTINEL_PORT", "8000"))

# GitHub OAuth Client ID for Device Flow (can be provided via settings/env)
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
