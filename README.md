# GitSentinel 🛡️

[![Build and Publish Releases](https://github.com/Byanski/GitSentinal/actions/workflows/release.yml/badge.svg)](https://github.com/Byanski/GitSentinal/actions/workflows/release.yml)
[![Releases](https://img.shields.io/github/v/release/Byanski/GitSentinal?include_prereleases&label=Latest%20Release)](https://github.com/Byanski/GitSentinal/releases)

**GitSentinel** is a lightweight, high-performance security scanner that connects to your GitHub account and inspects every line of code across all your repositories for exposed API keys, credentials, and environment variables.

It alerts you to the exact repository, file, and line number on GitHub, provides copy-paste remediation commands to purge secrets from your Git history, and can run silently in the background once a day with desktop notifications.

---

## Key Features

- **GitHub Sign-In**: Connect securely using either a **Personal Access Token (PAT)** or **OAuth Device Flow**. Credentials stay strictly local on your machine.
- **Deep Line-by-Line Scanning**: Analyzes code line-by-line across all files using high-precision regex signatures paired with Shannon entropy calculations to eliminate false positives.
- **Direct GitHub Line Links**: Jump directly to `github.com/{owner}/{repo}/blob/{branch}/{file}#L{line}` with one click to inspect the finding in context.
- **Lightweight & Fast**: In-memory tree-walking via GitHub's Git Trees API. No bulky disk clones or massive dependency trees.
- **Automated Daily Scan**: Background scheduling (`APScheduler`) configured right in the settings UI. Runs automatically once a day at your chosen time.
- **Desktop Toast Notifications**: Receive Windows desktop alerts when secrets or credentials are found during scheduled runs.
- **Actionable Remediation**: Built-in instructions with `git-filter-repo` commands to permanently remove leaked secrets from git commit history.
- **Masked Previews & Resolution Tracking**: Keep secrets safely masked with toggleable reveal buttons, and track findings as *Open*, *Resolved*, or *Ignored*.

---

## Secret Detection Rules

GitSentinel detects over a dozen major credential categories, including:
- **Cloud Providers**: AWS Access Key IDs (`AKIA...`), AWS Secret Keys, Google Cloud API keys (`AIza...`), Azure storage connection strings.
- **AI & LLM Services**: OpenAI API keys (`sk-...`, `sk-proj-...`), Anthropic API keys (`sk-ant-...`), Hugging Face tokens (`hf_...`).
- **Developer Platforms**: GitHub Personal Access Tokens (`ghp_...`, `gho_...`, `github_pat_...`), GitLab tokens, Slack tokens & webhooks, Discord bot tokens.
- **Payments & Communications**: Stripe Live Secret keys (`sk_live_...`), Twilio Auth Tokens, SendGrid API keys, Mailgun keys.
- **Private Keys**: RSA, OpenSSH, EC, PGP cryptographic private key headers.
- **Database Connection Strings**: PostgreSQL, MySQL, MongoDB, Redis connection URLs containing embedded user credentials.
- **Hardcoded Secrets & Environment Variables**: Generic `API_KEY=`, `SECRET=`, `PASSWORD=` assignments exceeding Shannon randomness thresholds.

---

## Downloads & Portable Binaries

Download pre-built standalone packages from the [Releases](https://github.com/Byanski/GitSentinal/releases) page:
- **Windows (.exe)**: [GitSentinel.exe](https://github.com/Byanski/GitSentinal/releases/latest/download/GitSentinel.exe) (single-file executable, zero install)
- **macOS Apple Silicon (.dmg)**: [GitSentinel-macOS-arm64.dmg](https://github.com/Byanski/GitSentinal/releases/latest/download/GitSentinel-macOS-arm64.dmg) (for M1/M2/M3/M4 Macs)
- **macOS Intel (.dmg)**: [GitSentinel-macOS-x86_64.dmg](https://github.com/Byanski/GitSentinal/releases/latest/download/GitSentinel-macOS-x86_64.dmg) (for Intel Macs)
- **Linux (.AppImage)**: [GitSentinel-x86_64.AppImage](https://github.com/Byanski/GitSentinal/releases/latest/download/GitSentinel-x86_64.AppImage) (portable executable, run with `chmod +x`)

---

## Quick Start (From Source)

### 1. Launch with One Click (Windows)
Double-click `run.bat` in the project root. It will install any missing dependencies and open `http://localhost:8000` in your default browser.

### 2. Manual Startup
```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open [http://localhost:8000](http://localhost:8000) in your web browser.

---

## Running Automated Tests

Run the test suite with:
```bash
python -m pytest
```

---

## Daily Auto-Run Configuration

Navigate to the **Settings** tab in the web interface:
1. Toggle **Enable Daily Auto-Scan** to ON.
2. Select your preferred daily scan time (e.g. `03:00` AM).
3. Ensure **Desktop Notifications** is enabled.
4. Click **Save Settings**.

The background scheduler will run silently and display a desktop notification upon completion if any leaked credentials are detected.
