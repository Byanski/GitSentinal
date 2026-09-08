import httpx
import base64
from typing import List, Dict, Any, Optional

GITHUB_API_BASE = "https://api.github.com"
GITHUB_OAUTH_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_OAUTH_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"

class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        self.token = token
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitSentinel-Secret-Scanner"
        }
        if token:
            headers["Authorization"] = f"token {token}"
        self.client = httpx.AsyncClient(headers=headers, timeout=25.0)

    async def close(self):
        await self.client.aclose()

    async def get_user_profile(self) -> Dict[str, Any]:
        """Fetch the authenticated user's profile."""
        resp = await self.client.get(f"{GITHUB_API_BASE}/user")
        if resp.status_code == 200:
            return resp.json()
        raise Exception(f"Failed to fetch user profile: {resp.status_code} {resp.text}")

    async def list_repositories(self, visibility: str = "all") -> List[Dict[str, Any]]:
        """List repositories accessible to the user."""
        all_repos = []
        page = 1
        while True:
            resp = await self.client.get(
                f"{GITHUB_API_BASE}/user/repos",
                params={
                    "visibility": visibility,
                    "affiliation": "owner,collaborator,organization_member",
                    "sort": "updated",
                    "per_page": 100,
                    "page": page
                }
            )
            if resp.status_code != 200:
                raise Exception(f"Failed to list repos: {resp.status_code} {resp.text}")
            
            data = resp.json()
            if not data:
                break

            for repo in data:
                all_repos.append({
                    "id": repo["id"],
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "private": repo["private"],
                    "html_url": repo["html_url"],
                    "default_branch": repo.get("default_branch", "main"),
                    "updated_at": repo.get("updated_at"),
                    "description": repo.get("description") or "",
                    "size_kb": repo.get("size", 0)
                })

            if len(data) < 100:
                break
            page += 1

        return all_repos

    async def get_repo_tree(self, owner: str, repo: str, branch: str) -> List[Dict[str, Any]]:
        """
        Fetch the entire file tree recursively using the Git Trees API.
        This provides file paths and SHAs in a single lightweight HTTP request.
        """
        resp = await self.client.get(
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"}
        )
        if resp.status_code == 200:
            data = resp.json()
            tree = data.get("tree", [])
            # Filter only blobs (files), ignore subtrees (directories)
            return [item for item in tree if item.get("type") == "blob"]
        elif resp.status_code == 409:
            # Git Repository is empty
            return []
        else:
            raise Exception(f"Failed to fetch tree for {owner}/{repo}: {resp.status_code} {resp.text}")

    async def fetch_file_content(self, owner: str, repo: str, path: str, branch: str) -> Optional[str]:
        """
        Fetch the raw text content of a file via GitHub API or raw content.
        """
        # Try raw media header to get decoded string directly
        headers = {
            "Accept": "application/vnd.github.v3.raw",
            "Authorization": f"token {self.token}" if self.token else ""
        }
        resp = await self.client.get(
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}?ref={branch}",
            headers=headers
        )
        if resp.status_code == 200:
            return resp.text
        
        # Fallback to standard contents json if needed
        if resp.status_code == 403 or resp.status_code == 404:
            return None
        return None

    # Static OAuth & Device Flow methods
    @staticmethod
    async def request_device_code(client_id: str, scope: str = "repo,read:user,user:email") -> Dict[str, Any]:
        """Request a device verification code from GitHub."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                GITHUB_OAUTH_DEVICE_CODE_URL,
                headers={"Accept": "application/json"},
                data={"client_id": client_id, "scope": scope}
            )
            if resp.status_code == 200:
                return resp.json()
            raise Exception(f"Failed to start device flow: {resp.status_code} {resp.text}")

    @staticmethod
    async def poll_device_access_token(client_id: str, device_code: str) -> Dict[str, Any]:
        """Poll GitHub for the user authorization token."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                GITHUB_OAUTH_ACCESS_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": client_id,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
                }
            )
            if resp.status_code == 200:
                return resp.json()
            raise Exception(f"Failed to poll device token: {resp.status_code} {resp.text}")
