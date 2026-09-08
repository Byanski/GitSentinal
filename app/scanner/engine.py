import asyncio
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from app.scanner.github_client import GitHubClient
from app.scanner.patterns import scan_line_for_secrets
from app.database import (
    create_scan_record,
    update_scan_record,
    save_finding,
    get_all_settings
)

class ScanState:
    def __init__(self):
        self.is_scanning = False
        self.scan_id: Optional[int] = None
        self.total_repos = 0
        self.scanned_repos = 0
        self.total_files_scanned = 0
        self.total_findings = 0
        self.current_repo = ""
        self.current_file = ""
        self.logs: List[str] = []
        self.error: Optional[str] = None
        self.cancel_requested = False

    def reset(self):
        self.is_scanning = True
        self.scan_id = None
        self.total_repos = 0
        self.scanned_repos = 0
        self.total_files_scanned = 0
        self.total_findings = 0
        self.current_repo = ""
        self.current_file = ""
        self.logs = []
        self.error = None
        self.cancel_requested = False

    def add_log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.logs.append(entry)
        if len(self.logs) > 300:
            self.logs = self.logs[-300:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_scanning": self.is_scanning,
            "scan_id": self.scan_id,
            "total_repos": self.total_repos,
            "scanned_repos": self.scanned_repos,
            "total_files_scanned": self.total_files_scanned,
            "total_findings": self.total_findings,
            "current_repo": self.current_repo,
            "current_file": self.current_file,
            "logs": self.logs[-50:],
            "error": self.error,
            "cancel_requested": self.cancel_requested
        }

# Global singleton scanner state
scanner_state = ScanState()

class ScanEngine:
    def __init__(self, github_token: str):
        self.token = github_token
        self.client = GitHubClient(token=github_token)

    def should_skip_file(self, path: str, size: int, excluded_exts: List[str], excluded_paths: List[str]) -> bool:
        """Determines if a file should be skipped based on path, extension, or size."""
        # Check size (skip files > 1MB for performance and memory)
        if size > 1024 * 1024:
            return True

        lower_path = path.lower()

        # Check path substrings
        for excl in excluded_paths:
            if excl and excl.lower() in lower_path:
                return True

        # Check extensions
        ext = os.path.splitext(lower_path)[1]
        if ext and ext in excluded_exts:
            return True

        return False

    async def scan_file_content(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
        min_entropy: float,
        scan_id: int
    ) -> int:
        """Fetch and scan a single file line-by-line."""
        try:
            content = await self.client.fetch_file_content(owner, repo, path, branch)
            if not content:
                return 0

            findings_count = 0
            lines = content.splitlines()

            for line_idx, line in enumerate(lines, start=1):
                # Don't scan excessively long lines like minified assets
                if len(line) > 1500:
                    continue

                detections = scan_line_for_secrets(line, min_entropy_threshold=min_entropy)
                for det in detections:
                    findings_count += 1
                    save_finding(
                        scan_id=scan_id,
                        repo_name=repo,
                        repo_full_name=f"{owner}/{repo}",
                        branch=branch,
                        file_path=path,
                        line_number=line_idx,
                        secret_type=det["secret_type"],
                        severity=det["severity"],
                        snippet=det["snippet"],
                        masked_secret=det["masked_secret"]
                    )
                    scanner_state.add_log(
                        f"🚨 Detected {det['secret_type']} in {owner}/{repo}:{path} (line {line_idx})"
                    )

            return findings_count
        except Exception as e:
            scanner_state.add_log(f"⚠️ Error reading {path}: {str(e)}")
            return 0

    async def scan_repository(
        self,
        repo: Dict[str, Any],
        excluded_exts: List[str],
        excluded_paths: List[str],
        min_entropy: float,
        scan_id: int,
        concurrency: int = 5
    ) -> int:
        """Scan all eligible files in a repository."""
        full_name = repo["full_name"]
        owner, repo_name = full_name.split("/")
        branch = repo.get("default_branch", "main")

        scanner_state.current_repo = full_name
        scanner_state.add_log(f"🔍 Inspecting repository: {full_name} (branch: {branch})")

        try:
            tree = await self.client.get_repo_tree(owner, repo_name, branch)
        except Exception as e:
            scanner_state.add_log(f"⚠️ Could not fetch tree for {full_name}: {str(e)}")
            return 0

        # Filter out ineligible files
        eligible_files = []
        for item in tree:
            path = item.get("path", "")
            size = item.get("size", 0)
            if not self.should_skip_file(path, size, excluded_exts, excluded_paths):
                eligible_files.append(item)

        scanner_state.add_log(f"📄 Found {len(eligible_files)} code files to scan in {full_name}")

        repo_findings = 0
        semaphore = asyncio.Semaphore(concurrency)

        async def worker(item: Dict[str, Any]):
            nonlocal repo_findings
            if scanner_state.cancel_requested:
                return

            path = item.get("path", "")
            scanner_state.current_file = path

            async with semaphore:
                f_count = await self.scan_file_content(
                    owner=owner,
                    repo=repo_name,
                    branch=branch,
                    path=path,
                    min_entropy=min_entropy,
                    scan_id=scan_id
                )
                repo_findings += f_count
                scanner_state.total_files_scanned += 1
                scanner_state.total_findings += f_count

        # Run tasks with concurrency limit
        tasks = [worker(item) for item in eligible_files]
        await asyncio.gather(*tasks, return_exceptions=True)

        return repo_findings

    async def run_scan(self, repo_full_names: Optional[List[str]] = None):
        """Run a full scan across all or selected user repositories."""
        if scanner_state.is_scanning:
            return

        scanner_state.reset()

        try:
            settings = get_all_settings()
            excluded_exts = [
                ext.strip().lower() for ext in settings.get("excluded_extensions", "").split(",") if ext.strip()
            ]
            excluded_paths = [
                p.strip() for p in settings.get("excluded_paths", "").split(",") if p.strip()
            ]
            min_entropy = float(settings.get("min_entropy", "3.0"))

            scanner_state.add_log("🚀 Initializing scan session...")
            
            # Fetch user repositories
            repos = await self.client.list_repositories()
            if repo_full_names:
                repos = [r for r in repos if r["full_name"] in repo_full_names]

            scanner_state.total_repos = len(repos)
            scanner_state.add_log(f"📦 Discovered {len(repos)} repositories to analyze")

            # Create scan history DB record
            scan_id = create_scan_record(total_repos=len(repos))
            scanner_state.scan_id = scan_id

            for repo in repos:
                if scanner_state.cancel_requested:
                    scanner_state.add_log("⏹️ Scan canceled by user")
                    break

                await self.scan_repository(
                    repo=repo,
                    excluded_exts=excluded_exts,
                    excluded_paths=excluded_paths,
                    min_entropy=min_entropy,
                    scan_id=scan_id
                )
                scanner_state.scanned_repos += 1
                update_scan_record(
                    scan_id,
                    scanned_repos=scanner_state.scanned_repos,
                    total_files=scanner_state.total_files_scanned,
                    total_findings=scanner_state.total_findings
                )

            status = "cancelled" if scanner_state.cancel_requested else "completed"
            update_scan_record(
                scan_id,
                status=status,
                completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )

            scanner_state.add_log(
                f"✅ Scan finished! Examined {scanner_state.total_files_scanned} files across {scanner_state.scanned_repos} repos. Found {scanner_state.total_findings} potential secret exposures."
            )

        except Exception as e:
            scanner_state.error = str(e)
            scanner_state.add_log(f"❌ Scan failed: {str(e)}")
            if scanner_state.scan_id:
                update_scan_record(
                    scanner_state.scan_id,
                    status="failed",
                    error_message=str(e),
                    completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
        finally:
            scanner_state.is_scanning = False
            scanner_state.current_repo = ""
            scanner_state.current_file = ""
            await self.client.close()
