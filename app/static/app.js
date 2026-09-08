// GitSentinel Client Application

let currentUser = null;
let currentRepos = [];
let scanPollInterval = null;
let activeFindings = [];

// Init on DOM ready
document.addEventListener("DOMContentLoaded", async () => {
  lucide.createIcons();
  await checkAuthStatus();
  await loadSettings();
  await loadStats();
  await checkScanStatus();
});

// Toast notification helper
function showToast(message, type = "info") {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toast-message");
  const iconEl = document.getElementById("toast-icon");

  msgEl.innerText = message;
  toast.classList.remove("translate-y-20", "opacity-0");

  setTimeout(() => {
    toast.classList.add("translate-y-20", "opacity-0");
  }, 4000);
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast("Command copied to clipboard!");
  });
}

// Tab Switching
function switchTab(tabName) {
  const tabs = ["dashboard", "findings", "settings"];
  tabs.forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    const btn = document.getElementById(`tab-btn-${t}`);
    if (t === tabName) {
      el.classList.remove("hidden");
      btn.className = "px-3.5 py-1.5 rounded-lg text-sm font-medium transition flex items-center space-x-2 bg-gray-800 text-white shadow-sm";
    } else {
      el.classList.add("hidden");
      btn.className = "px-3.5 py-1.5 rounded-lg text-sm font-medium transition flex items-center space-x-2 text-gray-400 hover:text-white hover:bg-gray-800/50";
    }
  });

  if (tabName === "findings") {
    loadFindings();
  } else if (tabName === "settings") {
    loadSettings();
  }
  lucide.createIcons();
}

// Authentication
async function checkAuthStatus() {
  try {
    const res = await fetch("/api/auth/status");
    const data = await res.json();
    const widget = document.getElementById("user-profile-widget");
    const banner = document.getElementById("unauth-banner");

    if (data.authenticated && data.user) {
      currentUser = data.user;
      banner.classList.add("hidden");

      const avatar = currentUser.avatar_url || "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png";
      widget.innerHTML = `
        <div class="flex items-center space-x-2.5 bg-gray-900/80 border border-gray-800 py-1 px-2.5 rounded-xl">
          <img src="${avatar}" alt="Avatar" class="w-6 h-6 rounded-full border border-gray-700">
          <div class="text-left hidden sm:block">
            <p class="text-xs font-semibold text-white leading-tight">${currentUser.name || currentUser.username}</p>
            <p class="text-[10px] text-gray-400">@${currentUser.username}</p>
          </div>
          <button onclick="logout()" title="Sign out" class="text-gray-400 hover:text-red-400 pl-1">
            <i data-lucide="log-out" class="w-4 h-4"></i>
          </button>
        </div>
      `;
      loadRepositories();
    } else {
      currentUser = null;
      banner.classList.remove("hidden");
      widget.innerHTML = `
        <button onclick="openAuthModal()" class="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold transition flex items-center space-x-2 shadow-sm">
          <i data-lucide="github" class="w-4 h-4"></i>
          <span>Sign In</span>
        </button>
      `;
    }
    lucide.createIcons();
  } catch (err) {
    console.error("Failed to check auth status", err);
  }
}

function openAuthModal() {
  document.getElementById("auth-modal").classList.remove("hidden");
  lucide.createIcons();
}

function closeAuthModal() {
  document.getElementById("auth-modal").classList.add("hidden");
}

async function submitPatLogin() {
  const input = document.getElementById("pat-input");
  const token = input.value.trim();
  if (!token) {
    showToast("Please enter a personal access token");
    return;
  }

  const btn = document.getElementById("btn-submit-pat");
  btn.disabled = true;
  btn.innerHTML = `<span>Connecting...</span>`;

  try {
    const res = await fetch("/api/auth/pat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token })
    });
    const data = await res.json();
    if (res.ok) {
      showToast("Successfully authenticated with GitHub!");
      closeAuthModal();
      input.value = "";
      await checkAuthStatus();
      await loadStats();
    } else {
      showToast(data.detail || "Authentication failed");
    }
  } catch (e) {
    showToast("Connection error: " + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span>Connect with Token</span>`;
  }
}

let devicePollTimer = null;
async function startDeviceAuth() {
  const clientId = document.getElementById("device-client-id-input").value.trim();
  if (!clientId) {
    showToast("Please provide a GitHub OAuth Client ID for device flow");
    return;
  }

  try {
    const res = await fetch("/api/auth/device/code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: clientId })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || "Failed to start device flow");
      return;
    }

    const infoBox = document.getElementById("device-flow-info");
    const codeEl = document.getElementById("device-flow-user-code");
    codeEl.innerText = data.user_code;
    infoBox.classList.remove("hidden");

    // Start polling
    const interval = (data.interval || 5) * 1000;
    if (devicePollTimer) clearInterval(devicePollTimer);

    devicePollTimer = setInterval(async () => {
      try {
        const pollRes = await fetch("/api/auth/device/poll", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ client_id: clientId, device_code: data.device_code })
        });
        const pollData = await pollRes.json();
        if (pollData.status === "success") {
          clearInterval(devicePollTimer);
          showToast("Authorized successfully via device flow!");
          closeAuthModal();
          await checkAuthStatus();
        } else if (pollData.error && pollData.error !== "authorization_pending") {
          clearInterval(devicePollTimer);
          showToast("Device authorization failed: " + pollData.error);
        }
      } catch (err) {
        clearInterval(devicePollTimer);
      }
    }, interval);

  } catch (e) {
    showToast("Error: " + e.message);
  }
}

async function logout() {
  try {
    await fetch("/api/auth/logout", { method: "POST" });
    showToast("Signed out");
    currentUser = null;
    await checkAuthStatus();
    await loadStats();
  } catch (e) {
    console.error(e);
  }
}

// Repositories
async function loadRepositories() {
  try {
    const res = await fetch("/api/repos");
    if (!res.ok) return;
    const data = await res.json();
    currentRepos = data.repos || [];

    document.getElementById("stat-total-repos").innerText = currentRepos.length;

    // Populate Repo Scope Selector Checkboxes
    const container = document.getElementById("repo-checkbox-list");
    container.innerHTML = "";
    currentRepos.forEach(repo => {
      const label = document.createElement("label");
      label.className = "flex items-center space-x-2 text-xs text-gray-300 hover:text-white cursor-pointer";
      label.innerHTML = `
        <input type="checkbox" name="selected-repos" value="${repo.full_name}" class="accent-cyan-500 rounded">
        <span>${repo.full_name}</span>
        ${repo.private ? '<span class="text-[10px] px-1 bg-gray-800 text-gray-400 rounded">private</span>' : ''}
      `;
      container.appendChild(label);
    });

    // Populate Findings Filter Dropdown
    const filterSelect = document.getElementById("filter-repo");
    filterSelect.innerHTML = `<option value="">All Repositories</option>`;
    currentRepos.forEach(repo => {
      const opt = document.createElement("option");
      opt.value = repo.full_name;
      opt.innerText = repo.full_name;
      filterSelect.appendChild(opt);
    });
  } catch (e) {
    console.error("Failed to load repos", e);
  }
}

function toggleScopeMode() {
  const selectedScope = document.querySelector('input[name="scan-scope"]:checked').value;
  const repoBox = document.getElementById("repo-select-container");
  if (selectedScope === "custom") {
    repoBox.classList.remove("hidden");
  } else {
    repoBox.classList.add("hidden");
  }
}

// Scanning Orchestration
async function triggerScan() {
  if (!currentUser) {
    openAuthModal();
    return;
  }

  const selectedScope = document.querySelector('input[name="scan-scope"]:checked').value;
  let targetRepos = null;

  if (selectedScope === "custom") {
    const checked = Array.from(document.querySelectorAll('input[name="selected-repos"]:checked')).map(cb => cb.value);
    if (checked.length === 0) {
      showToast("Please select at least one repository to scan");
      return;
    }
    targetRepos = checked;
  }

  const btnStart = document.getElementById("btn-start-scan");
  btnStart.disabled = true;

  try {
    const res = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repos: targetRepos })
    });

    const data = await res.json();
    if (res.ok) {
      showToast("Repository scan initialized!");
      startScanPolling();
    } else {
      showToast(data.detail || "Failed to start scan");
      btnStart.disabled = false;
    }
  } catch (e) {
    showToast("Error starting scan: " + e.message);
    btnStart.disabled = false;
  }
}

async function cancelScan() {
  try {
    await fetch("/api/scan/cancel", { method: "POST" });
    showToast("Cancellation requested...");
  } catch (e) {
    console.error(e);
  }
}

function startScanPolling() {
  const progressBox = document.getElementById("scan-progress-box");
  const btnStart = document.getElementById("btn-start-scan");
  const btnCancel = document.getElementById("btn-cancel-scan");

  progressBox.classList.remove("hidden");
  btnStart.classList.add("hidden");
  btnCancel.classList.remove("hidden");

  if (scanPollInterval) clearInterval(scanPollInterval);

  scanPollInterval = setInterval(async () => {
    await checkScanStatus();
  }, 1000);
}

async function checkScanStatus() {
  try {
    const res = await fetch("/api/scan/status");
    const state = await res.json();

    const progressBox = document.getElementById("scan-progress-box");
    const btnStart = document.getElementById("btn-start-scan");
    const btnCancel = document.getElementById("btn-cancel-scan");

    if (state.is_scanning) {
      progressBox.classList.remove("hidden");
      btnStart.classList.add("hidden");
      btnCancel.classList.remove("hidden");

      const pct = state.total_repos > 0 ? Math.round((state.scanned_repos / state.total_repos) * 100) : 5;
      document.getElementById("scan-progress-bar").style.width = `${pct}%`;
      document.getElementById("scan-progress-percentage").innerText = `${pct}%`;

      document.getElementById("scan-current-repo-label").innerText = state.current_repo ? `Scanning: ${state.current_repo}` : "Preparing...";
      document.getElementById("scan-current-file-label").innerText = state.current_file || "Reading repository tree...";
      document.getElementById("scan-files-counter").innerText = state.total_files_scanned;
      document.getElementById("scan-findings-counter").innerText = state.total_findings;

      // Update live logs
      const logContainer = document.getElementById("scan-live-logs");
      if (state.logs && state.logs.length > 0) {
        logContainer.innerHTML = state.logs.map(log => `<div>${escapeHtml(log)}</div>`).join("");
        logContainer.scrollTop = logContainer.scrollHeight;
      }

      if (!scanPollInterval) {
        scanPollInterval = setInterval(checkScanStatus, 1000);
      }
    } else {
      if (scanPollInterval) {
        clearInterval(scanPollInterval);
        scanPollInterval = null;
        btnStart.classList.remove("hidden");
        btnStart.disabled = false;
        btnCancel.classList.add("hidden");
        
        await loadStats();
        await loadFindings();
        showToast("Scan finished!");
      }
    }
  } catch (e) {
    console.error("Failed to check scan status", e);
  }
}

// Findings
async function loadFindings() {
  const repoFilter = document.getElementById("filter-repo").value;
  const statusFilter = document.getElementById("filter-status").value;

  const url = new URL("/api/findings", window.location.origin);
  if (repoFilter) url.searchParams.set("repo", repoFilter);
  if (statusFilter) url.searchParams.set("status", statusFilter);

  try {
    const res = await fetch(url.toString());
    const data = await res.json();
    activeFindings = data.findings || [];

    // Update nav badge count
    const openCount = activeFindings.filter(f => f.status === "open").length;
    const badge = document.getElementById("nav-findings-badge");
    if (openCount > 0) {
      badge.innerText = openCount;
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }

    renderFindings(activeFindings);
  } catch (e) {
    console.error("Failed to load findings", e);
  }
}

function renderFindings(findings) {
  const container = document.getElementById("findings-container");
  if (findings.length === 0) {
    container.innerHTML = `
      <div class="text-center py-16 text-gray-500 space-y-3 bg-[#161b22] border border-gray-800 rounded-2xl">
        <i data-lucide="shield-check" class="w-10 h-10 mx-auto text-emerald-400"></i>
        <p class="text-base font-semibold text-gray-300">Clean! No Secrets Found</p>
        <p class="text-xs text-gray-500 max-w-sm mx-auto">No exposed API keys or environment variables were detected matching your filter criteria.</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }

  container.innerHTML = findings.map(f => {
    const severityClass = f.severity === "CRITICAL" ? "badge-critical" : f.severity === "HIGH" ? "badge-high" : "badge-medium";
    const githubFileUrl = `https://github.com/${f.repo_full_name}/blob/${f.branch}/${f.file_path}#L${f.line_number}`;
    
    return `
      <div class="bg-[#161b22] border border-gray-800 hover:border-gray-700 transition rounded-2xl p-5 space-y-4 shadow-sm" id="finding-card-${f.id}">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div class="flex items-center space-x-2.5 flex-wrap">
            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full ${severityClass}">
              ${f.severity}
            </span>
            <span class="text-sm font-bold text-white">${escapeHtml(f.secret_type)}</span>
            <span class="text-xs text-gray-400 font-mono">in <strong class="text-gray-200">${escapeHtml(f.repo_full_name)}</strong></span>
          </div>
          
          <div class="flex items-center space-x-2">
            <a href="${githubFileUrl}" target="_blank" class="px-3 py-1.5 rounded-xl bg-gray-900 border border-gray-800 hover:border-cyan-500/50 text-cyan-400 text-xs font-semibold transition flex items-center space-x-1.5">
              <span>GitHub Line ${f.line_number}</span>
              <i data-lucide="external-link" class="w-3.5 h-3.5"></i>
            </a>
            <button onclick="openRemediationModal(${f.id})" class="px-3 py-1.5 rounded-xl bg-blue-600/20 text-blue-400 border border-blue-500/30 hover:bg-blue-600/30 text-xs font-semibold transition flex items-center space-x-1">
              <i data-lucide="wrench" class="w-3.5 h-3.5"></i>
              <span>Fix</span>
            </button>
            <button onclick="openRemediationModal(${f.id}, true)" class="px-3 py-1.5 rounded-xl bg-purple-600/20 text-purple-300 border border-purple-500/30 hover:bg-purple-600/30 text-xs font-semibold transition flex items-center space-x-1" title="Generate AI prompt to clone, fix, and push">
              <i data-lucide="sparkles" class="w-3.5 h-3.5"></i>
              <span>Fix with AI</span>
            </button>
          </div>
        </div>

        <!-- File Path & Location -->
        <div class="flex items-center space-x-2 text-xs text-gray-400 font-mono bg-gray-900/60 px-3 py-1.5 rounded-lg border border-gray-800/80">
          <i data-lucide="file-code" class="w-4 h-4 text-gray-500"></i>
          <span class="text-gray-200">${escapeHtml(f.file_path)}</span>
          <span class="text-gray-500">:${f.line_number}</span>
        </div>

        <!-- Snippet -->
        <div class="space-y-1.5">
          <div class="terminal-box rounded-xl p-3 text-xs text-gray-300 font-mono overflow-x-auto flex items-center justify-between gap-2">
            <div class="truncate">
              <span class="text-gray-500 mr-2 select-none">${f.line_number} |</span>
              <span>${escapeHtml(f.snippet)}</span>
            </div>
            <div class="flex items-center space-x-2 shrink-0">
              <span class="text-[11px] px-2 py-0.5 rounded bg-gray-800 border border-gray-700 text-cyan-300 font-mono" id="secret-preview-${f.id}">
                ${escapeHtml(f.masked_secret)}
              </span>
            </div>
          </div>
        </div>

        <!-- Finding Footer Actions -->
        <div class="flex items-center justify-between text-xs text-gray-500 pt-1 border-t border-gray-800/50">
          <span>Detected: ${f.created_at}</span>
          <div class="flex items-center space-x-2">
            ${f.status === "open" ? `
              <button onclick="updateStatus(${f.id}, 'resolved')" class="text-emerald-400 hover:underline flex items-center gap-1">
                <i data-lucide="check" class="w-3.5 h-3.5"></i>
                <span>Mark Resolved</span>
              </button>
              <span class="text-gray-700">|</span>
              <button onclick="updateStatus(${f.id}, 'ignored')" class="text-gray-400 hover:underline flex items-center gap-1">
                <i data-lucide="eye-off" class="w-3.5 h-3.5"></i>
                <span>Ignore</span>
              </button>
            ` : `
              <span class="capitalize font-medium text-gray-400">Status: ${f.status}</span>
              <button onclick="updateStatus(${f.id}, 'open')" class="text-cyan-400 hover:underline ml-2">Reopen</button>
            `}
          </div>
        </div>
      </div>
    `;
  }).join("");

  lucide.createIcons();
}

async function updateStatus(findingId, status) {
  try {
    const res = await fetch(`/api/findings/${findingId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status })
    });
    if (res.ok) {
      showToast(`Marked finding as ${status}`);
      await loadFindings();
      await loadStats();
    }
  } catch (e) {
    console.error(e);
  }
}

// AI Remediation Prompt Builder
function buildAiRemediationPrompt(finding) {
  const repoName = finding.repo_name || (finding.repo_full_name ? finding.repo_full_name.split("/")[1] : "repository");
  const branch = finding.branch || "main";

  return `You are an expert full-stack developer and security engineer.

TASK:
A leaked credential / environment variable was detected in repository "${finding.repo_full_name}". Clone the repo, target the issue, fix the code to read the secret from environment variables, purge it from git history, and push the clean code back to GitHub.

TARGET SPECIFICATIONS:
- Repository: https://github.com/${finding.repo_full_name}.git
- Default Branch: ${branch}
- Affected File: ${finding.file_path}
- Line Number: ${finding.line_number}
- Secret Type: ${finding.secret_type} (${finding.severity} Severity)
- Leaked Snippet: ${finding.snippet}

STEP-BY-STEP INSTRUCTIONS:
1. CLONE THE REPO & CHECKOUT BRANCH:
   git clone https://github.com/${finding.repo_full_name}.git
   cd ${repoName}
   git checkout ${branch}

2. TARGET & FIX THE ISSUE:
   - Open "${finding.file_path}" around line ${finding.line_number}.
   - Remove the hardcoded secret / API key / environment variable.
   - Refactor the code to read this value dynamically from an environment variable (for example, process.env in JavaScript/TypeScript, os.environ.get in Python, System.getenv in Java, or language equivalent).
   - Ensure the application provides a clear error or warning if the variable is not set.

3. SET UP SECURE ENVIRONMENT CONFIG:
   - Add a placeholder entry in ".env.example" (e.g. API_KEY="your_key_here") so developers know the required variable.
   - Verify that ".env" and any sensitive files are strictly excluded in ".gitignore".

4. PURGE FROM GIT HISTORY:
   - Because the key was already committed, run git-filter-repo to erase it from previous commits:
     git filter-repo --invert-paths --path "${finding.file_path}"

5. VERIFY AND PUSH:
   - Run tests or test build to verify everything runs cleanly.
   - Commit and push back to GitHub:
     git add .
     git commit -m "security: remove hardcoded ${finding.secret_type} and load from env"
     git push origin ${branch} --force
`;
}

// Remediation Modal
function openRemediationModal(findingId, autoCopy = false) {
  const finding = activeFindings.find(f => f.id === findingId);
  if (!finding) return;

  document.getElementById("modal-finding-subtitle").innerText = `${finding.secret_type} in ${finding.file_path}:${finding.line_number}`;
  document.getElementById("modal-git-command").innerText = `git filter-repo --invert-paths --path "${finding.file_path}"`;

  // Generate engineered AI prompt
  const promptText = buildAiRemediationPrompt(finding);
  const promptEl = document.getElementById("modal-ai-prompt");
  if (promptEl) {
    promptEl.value = promptText;
  }

  document.getElementById("remediation-modal").classList.remove("hidden");
  lucide.createIcons();

  if (autoCopy) {
    copyAiPrompt();
  }
}

function copyAiPrompt() {
  const promptEl = document.getElementById("modal-ai-prompt");
  if (!promptEl || !promptEl.value) return;

  navigator.clipboard.writeText(promptEl.value).then(() => {
    const btnText = document.getElementById("copy-ai-btn-text");
    if (btnText) {
      btnText.innerText = "Copied!";
      setTimeout(() => { btnText.innerText = "Copy AI Prompt"; }, 2500);
    }
    showToast("🤖 AI Fix Prompt copied! Paste into your AI coding assistant.");
  });
}

function closeRemediationModal() {
  document.getElementById("remediation-modal").classList.add("hidden");
}

// Stats
async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    document.getElementById("stat-open-findings").innerText = data.total_open;
    document.getElementById("stat-critical-findings").innerText = data.critical_open;
    document.getElementById("stat-resolved-findings").innerText = data.resolved;

    // Findings nav badge
    const badge = document.getElementById("nav-findings-badge");
    if (data.total_open > 0) {
      badge.innerText = data.total_open;
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }
  } catch (e) {
    console.error("Failed to load stats", e);
  }
}

// Settings
async function loadSettings() {
  try {
    const res = await fetch("/api/settings");
    const data = await res.json();
    const s = data.settings;

    const dailyEnabled = s.daily_scan_enabled === "true";
    document.getElementById("setting-daily-scan-enabled").checked = dailyEnabled;
    document.getElementById("setting-daily-scan-time").value = s.daily_scan_time || "03:00";
    document.getElementById("setting-desktop-notifications").checked = s.desktop_notifications === "true";
    document.getElementById("setting-excluded-extensions").value = s.excluded_extensions || "";
    document.getElementById("setting-excluded-paths").value = s.excluded_paths || "";
    document.getElementById("setting-min-entropy").value = s.min_entropy || "3.2";
    document.getElementById("entropy-val").innerText = s.min_entropy || "3.2";

    // Update Header Pill
    const dot = document.getElementById("scheduler-dot");
    const label = document.getElementById("scheduler-text");
    const pill = document.getElementById("auto-scan-status-pill");

    pill.classList.remove("hidden");
    if (dailyEnabled) {
      dot.className = "w-2 h-2 rounded-full bg-emerald-400 animate-pulse";
      label.innerText = `Auto-scan active at ${s.daily_scan_time}`;
    } else {
      dot.className = "w-2 h-2 rounded-full bg-gray-500";
      label.innerText = "Daily scan off";
    }
  } catch (e) {
    console.error("Failed to load settings", e);
  }
}

async function saveSettings(e) {
  e.preventDefault();
  const settings = {
    daily_scan_enabled: document.getElementById("setting-daily-scan-enabled").checked ? "true" : "false",
    daily_scan_time: document.getElementById("setting-daily-scan-time").value,
    desktop_notifications: document.getElementById("setting-desktop-notifications").checked ? "true" : "false",
    excluded_extensions: document.getElementById("setting-excluded-extensions").value,
    excluded_paths: document.getElementById("setting-excluded-paths").value,
    min_entropy: document.getElementById("setting-min-entropy").value
  };

  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ settings })
    });
    if (res.ok) {
      showToast("Settings updated successfully!");
      await loadSettings();
    } else {
      showToast("Failed to save settings");
    }
  } catch (err) {
    showToast("Error saving settings: " + err.message);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
