import sys
import os
import time
import threading
import webbrowser
import uvicorn
from app.main import app
from app.config import HOST, PORT

def auto_open_browser():
    time.sleep(1.2)
    webbrowser.open(f"http://{HOST}:{PORT}")

if __name__ == "__main__":
    # Open browser automatically on launch
    threading.Thread(target=auto_open_browser, daemon=True).start()
    print("==================================================")
    print(f" GitSentinel is live at http://{HOST}:{PORT}")
    print(" Press Ctrl+C to stop.")
    print("==================================================")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
