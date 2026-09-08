import asyncio
import os
import logging
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from app.config import STATIC_DIR, GITHUB_CLIENT_ID, HOST, PORT
from app.database import (
    init_db,
    get_auth,
    save_auth,
    clear_auth,
    get_all_settings,
    update_setting,
    get_findings,
    update_finding_status,
    get_stats
)
from app.scanner.github_client import GitHubClient
from app.scanner.engine import ScanEngine, scanner_state
from app.scheduler.runner import configure_scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("gitsentinel")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing GitSentinel database...")
    init_db()
    logger.info("Configuring background scheduler...")
    configure_scheduler()
    yield
    # Shutdown
    logger.info("Shutting down GitSentinel...")

app = FastAPI(title="GitSentinel", lifespan=lifespan)

# Static files mount
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Request Models
class PatAuthRequest(BaseModel):
    token: str

class DeviceCodeRequest(BaseModel):
    client_id: Optional[str] = None

class DevicePollRequest(BaseModel):
    client_id: str
    device_code: str

class ScanStartRequest(BaseModel):
    repos: Optional[List[str]] = None

class StatusUpdateRequest(BaseModel):
    status: str

class SettingsUpdateRequest(BaseModel):
    settings: Dict[str, str]

# Web Route
@app.get("/")
async def serve_index():
    return FileResponse(STATIC_DIR / "index.html")

# Authentication Endpoints
@app.get("/api/auth/status")
async def get_auth_status():
    auth = get_auth()
    if not auth:
        return {"authenticated": False, "user": None}
    
    # Return user details without exposing full token to client UI
    masked_token = auth["access_token"][:6] + "..." + auth["access_token"][-4:] if len(auth["access_token"]) > 10 else "***"
    return {
        "authenticated": True,
        "user": {
            "username": auth.get("username"),
            "name": auth.get("name"),
            "avatar_url": auth.get("avatar_url"),
            "email": auth.get("email"),
            "auth_type": auth.get("auth_type"),
            "masked_token": masked_token
        }
    }

@app.post("/api/auth/pat")
async def login_with_pat(req: PatAuthRequest):
    token = req.token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token cannot be empty")

    client = GitHubClient(token=token)
    try:
        user_info = await client.get_user_profile()
        save_auth(
            access_token=token,
            username=user_info.get("login"),
            name=user_info.get("name"),
            avatar_url=user_info.get("avatar_url"),
            email=user_info.get("email"),
            auth_type="pat"
        )
        return {"success": True, "user": user_info}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"GitHub token validation failed: {str(e)}")
    finally:
        await client.close()

@app.post("/api/auth/device/code")
async def start_device_flow(req: DeviceCodeRequest):
    client_id = req.client_id or GITHUB_CLIENT_ID
    if not client_id:
        raise HTTPException(
            status_code=400,
            detail="GitHub OAuth Client ID is required for Device Flow. You can provide one or use a Personal Access Token instead."
        )
    try:
        data = await GitHubClient.request_device_code(client_id)
        return data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/device/poll")
async def poll_device_flow(req: DevicePollRequest):
    try:
        token_data = await GitHubClient.poll_device_access_token(req.client_id, req.device_code)
        if "access_token" in token_data:
            access_token = token_data["access_token"]
            client = GitHubClient(token=access_token)
            user_info = await client.get_user_profile()
            await client.close()

            save_auth(
                access_token=access_token,
                username=user_info.get("login"),
                name=user_info.get("name"),
                avatar_url=user_info.get("avatar_url"),
                email=user_info.get("email"),
                auth_type="oauth"
            )
            return {"status": "success", "user": user_info}
        elif "error" in token_data:
            return {"status": "pending", "error": token_data["error"], "error_description": token_data.get("error_description", "")}
        return {"status": "pending"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/logout")
async def logout():
    clear_auth()
    return {"success": True}

# Repository Endpoints
@app.get("/api/repos")
async def list_repositories():
    auth = get_auth()
    if not auth:
        raise HTTPException(status_code=401, detail="Not authenticated")
    client = GitHubClient(token=auth["access_token"])
    try:
        repos = await client.list_repositories()
        return {"repos": repos}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.close()

# Scan Endpoints
@app.post("/api/scan/start")
async def start_scan(req: ScanStartRequest, background_tasks: BackgroundTasks):
    auth = get_auth()
    if not auth:
        raise HTTPException(status_code=401, detail="Please sign in to GitHub before scanning.")
    
    if scanner_state.is_scanning:
        raise HTTPException(status_code=409, detail="A scan is already actively running.")

    engine = ScanEngine(auth["access_token"])
    # Run scan in asyncio background task
    asyncio.create_task(engine.run_scan(repo_full_names=req.repos))
    return {"message": "Scan started", "status": scanner_state.to_dict()}

@app.post("/api/scan/cancel")
async def cancel_scan():
    if not scanner_state.is_scanning:
        return {"message": "No scan is currently running"}
    scanner_state.cancel_requested = True
    scanner_state.add_log("🛑 User requested scan cancellation...")
    return {"message": "Scan cancellation requested"}

@app.get("/api/scan/status")
async def get_scan_status():
    return scanner_state.to_dict()

# Findings Endpoints
@app.get("/api/findings")
async def list_findings(repo: Optional[str] = None, status: Optional[str] = None, scan_id: Optional[int] = None):
    items = get_findings(repo=repo, status=status, scan_id=scan_id)
    return {"findings": items}

@app.post("/api/findings/{finding_id}/status")
async def change_finding_status(finding_id: int, req: StatusUpdateRequest):
    if req.status not in ["open", "resolved", "ignored"]:
        raise HTTPException(status_code=400, detail="Invalid status value")
    update_finding_status(finding_id, req.status)
    return {"success": True, "finding_id": finding_id, "status": req.status}

# Statistics & Summary
@app.get("/api/stats")
async def get_dashboard_stats():
    return get_stats()

# Settings Endpoints
@app.get("/api/settings")
async def get_settings():
    return {"settings": get_all_settings()}

@app.post("/api/settings")
async def update_settings(req: SettingsUpdateRequest):
    for k, v in req.settings.items():
        update_setting(k, v)
    # Reconfigure scheduler with updated settings
    configure_scheduler()
    return {"success": True, "settings": get_all_settings()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)
