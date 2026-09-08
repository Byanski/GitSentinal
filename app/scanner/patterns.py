import re
import math
from typing import List, Dict, Any, Optional

def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def mask_secret(secret: str) -> str:
    """Mask a secret for display, showing only the first few and last few chars."""
    if len(secret) <= 8:
        return "*" * len(secret)
    prefix_len = min(4, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    masked_middle = "*" * max(4, len(secret) - prefix_len - suffix_len)
    return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"

# Common placeholder words that trigger false positives
FALSE_POSITIVE_PATTERNS = [
    r"^your[-_]?api[-_]?key",
    r"^my[-_]?secret",
    r"^placeholder",
    r"^change[-_]?me",
    r"^replace[-_]?me",
    r"^dummy[-_]?key",
    r"^todo",
    r"^fixme",
    r"^sample[-_]?key",
    r"^insert[-_]?here",
    r"^fake[-_]?key"
]

def is_false_positive(value: str) -> bool:
    """Heuristic check to filter out non-secrets and common placeholders."""
    val_lower = value.lower()
    
    # Check if contains templating or placeholder syntax
    if any(wrapper in val_lower for wrapper in ["${", "{{", "%{", "<your", "<api", "[your"]):
        return True
        
    # Check if it's explicitly a test or mock key prefix
    if val_lower.startswith(("sk_test_", "pk_test_", "mock_", "fake_")):
        return True

    # Exact match on common placeholder strings
    common_exact = {"your_api_key_here", "placeholder_token", "dummy", "xxxx", "123456789", "00000000"}
    if val_lower in common_exact:
        return True

    # Regex patterns for placeholder prefixes
    for pat in FALSE_POSITIVE_PATTERNS:
        if re.search(pat, val_lower):
            return True

    # If all characters are the same or purely 2 distinct characters
    if len(set(value)) <= 2:
        return True

    return False

# Rule definitions
RULES: List[Dict[str, Any]] = [
    # Cloud & Infrastructure
    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"),
        "extract_group": 1,
        "min_entropy": 3.0,
        "category": "Cloud"
    },
    {
        "id": "aws_secret_key",
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "extract_group": 1,
        "min_entropy": 4.0,
        "category": "Cloud"
    },
    {
        "id": "gcp_api_key",
        "name": "Google Cloud API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(?:^|[^A-Za-z0-9_-])(AIza[0-9A-Za-z-_]{35})(?:[^A-Za-z0-9_-]|$)"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "Cloud"
    },
    {
        "id": "azure_connection_string",
        "name": "Azure Storage Connection String",
        "severity": "CRITICAL",
        "regex": re.compile(r"(DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{60,100};?)"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "Cloud"
    },

    # AI & Machine Learning
    {
        "id": "openai_api_key",
        "name": "OpenAI API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(sk-proj-[A-Za-z0-9_-]{48,}|sk-[a-zA-Z0-9]{32,})"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "AI"
    },
    {
        "id": "anthropic_api_key",
        "name": "Anthropic API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(sk-ant-[a-zA-Z0-9_\-]{32,})"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "AI"
    },
    {
        "id": "huggingface_token",
        "name": "Hugging Face User Token",
        "severity": "HIGH",
        "regex": re.compile(r"(hf_[a-zA-Z0-9]{34,})"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "AI"
    },

    # GitHub & Developer Platforms
    {
        "id": "github_pat",
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "regex": re.compile(r"(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "VCS"
    },
    {
        "id": "gitlab_pat",
        "name": "GitLab Personal Access Token",
        "severity": "HIGH",
        "regex": re.compile(r"(glpat-[0-9a-zA-Z_\-]{20,})"),
        "extract_group": 1,
        "min_entropy": 3.2,
        "category": "VCS"
    },
    {
        "id": "slack_token",
        "name": "Slack Token",
        "severity": "HIGH",
        "regex": re.compile(r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)"),
        "extract_group": 1,
        "min_entropy": 3.2,
        "category": "Chat"
    },
    {
        "id": "slack_webhook",
        "name": "Slack Webhook URL",
        "severity": "HIGH",
        "regex": re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+)"),
        "extract_group": 1,
        "min_entropy": 3.0,
        "category": "Chat"
    },
    {
        "id": "discord_bot_token",
        "name": "Discord Bot Token",
        "severity": "HIGH",
        "regex": re.compile(r"(?:^|[^A-Za-z0-9_\-])([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})(?:[^A-Za-z0-9_\-]|$)"),
        "extract_group": 1,
        "min_entropy": 3.8,
        "category": "Chat"
    },
    {
        "id": "discord_webhook",
        "name": "Discord Webhook",
        "severity": "MEDIUM",
        "regex": re.compile(r"(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)"),
        "extract_group": 1,
        "min_entropy": 3.0,
        "category": "Chat"
    },

    # Payments & Communications
    {
        "id": "stripe_secret_key",
        "name": "Stripe Live Secret Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "Payment"
    },
    {
        "id": "sendgrid_api_key",
        "name": "SendGrid API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})"),
        "extract_group": 1,
        "min_entropy": 3.8,
        "category": "Email"
    },
    {
        "id": "twilio_auth_token",
        "name": "Twilio Auth Token / API Key",
        "severity": "HIGH",
        "regex": re.compile(r"(?i)(?:twilio_auth_token|twilio_api_key|twilio_secret)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"),
        "extract_group": 1,
        "min_entropy": 3.0,
        "category": "Comms"
    },

    # Cryptographic Private Keys
    {
        "id": "private_key",
        "name": "Private Cryptographic Key Header",
        "severity": "CRITICAL",
        "regex": re.compile(r"(-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)? PRIVATE KEY-----)"),
        "extract_group": 1,
        "min_entropy": 0.0,
        "category": "Crypto"
    },

    # Database URLs
    {
        "id": "database_url_credentials",
        "name": "Database Connection String with Credentials",
        "severity": "CRITICAL",
        "regex": re.compile(r"((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_\-\.]+:[^@\s/]+@[a-zA-Z0-9_\-\.]+(:[0-9]+)?/[a-zA-Z0-9_\-\.]+)"),
        "extract_group": 1,
        "min_entropy": 3.0,
        "category": "Database"
    },

    # Generic Environment Variables / Hardcoded Secrets
    {
        "id": "generic_secret_assignment",
        "name": "Hardcoded Secret / API Key in Code or .env",
        "severity": "HIGH",
        "regex": re.compile(r"(?i)(?:api_key|apikey|secret_key|client_secret|auth_token|access_token|private_key|database_password|db_password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-~@#%^&+=]{12,128})['\"]"),
        "extract_group": 1,
        "min_entropy": 3.5,
        "category": "Generic"
    }
]

def scan_line_for_secrets(line: str, min_entropy_threshold: float = 3.0) -> List[Dict[str, Any]]:
    """
    Scans a single line of text against all secret rules.
    Returns a list of matching secret detections.
    """
    line_findings = []
    
    # Quick filter: ignore lines with comments describing placeholder instructions
    clean_line = line.strip()
    if clean_line.startswith(("// TODO", "# TODO", "/* TODO", "* TODO", "// NOTE", "# NOTE")):
        return []

    for rule in RULES:
        matches = rule["regex"].finditer(line)
        for match in matches:
            extracted = match.group(rule["extract_group"])
            if not extracted:
                continue

            # Check false positive heuristics
            if is_false_positive(extracted):
                continue

            # Check entropy requirements
            required_entropy = max(rule["min_entropy"], min_entropy_threshold)
            actual_entropy = calculate_shannon_entropy(extracted)

            if rule["id"] != "private_key" and actual_entropy < required_entropy:
                continue

            # Avoid duplicate matches on same extracted token
            snippet = clean_line
            if len(snippet) > 160:
                # Truncate overly long lines around the match
                start_idx = max(0, match.start() - 30)
                end_idx = min(len(line), match.end() + 30)
                snippet = "..." + line[start_idx:end_idx].strip() + "..."

            line_findings.append({
                "rule_id": rule["id"],
                "secret_type": rule["name"],
                "severity": rule["severity"],
                "category": rule["category"],
                "raw_secret": extracted,
                "masked_secret": mask_secret(extracted),
                "snippet": snippet,
                "entropy": round(actual_entropy, 2)
            })

    return line_findings
