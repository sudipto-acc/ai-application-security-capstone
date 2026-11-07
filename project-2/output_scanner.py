import re


SENSITIVE_PATTERNS = [
    # Database connection strings
    re.compile(
        r"postgres(?:ql)?://[^\s\"'<>]+",
        re.IGNORECASE
    ),

    # API keys: preserve the label, redact the value
    re.compile(
        r"(?P<label>api[_ -]?key\s*[:=]\s*)[A-Za-z0-9_\-]{12,}",
        re.IGNORECASE
    ),

    re.compile(
        r"(?P<label>(?:password|passwd)\s*[:=]\s*)[^\s,;]+",
        re.IGNORECASE
    ),

    # Synthetic canary and internal identifiers
    re.compile(
        r"TC-DEMO-CANARY-7419|ORCHID-TRAINING|HELP-DESK-DEMO",
        re.IGNORECASE
    ),

    # Unix internal file paths
    re.compile(
        r"/(?:srv|etc|opt|var|home)/[A-Za-z0-9_./-]+",
        re.IGNORECASE
    ),

    # Internal hostnames
    re.compile(
        r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.internal(?:\.[A-Za-z0-9-]+)*\b",
        re.IGNORECASE
    ),
]


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)


def scan_output(response):
    """
    Scan model output and redact sensitive information.

    Returns:
        (sanitized_response, findings)
    """

    if not isinstance(response, str):
        return "", ["Invalid model response type"]

    sanitized = response
    findings = []

    for pattern in SENSITIVE_PATTERNS:
        if pattern.groups:
            sanitized, count = pattern.subn(
                lambda match: (
                    match.groupdict().get("label", "")
                    + "[REDACTED]"
                ),
                sanitized
            )
        else:
            sanitized, count = pattern.subn(
                "[REDACTED]",
                sanitized
            )

        if count:
            findings.append("Sensitive information detected")

    # URLs are flagged for review, not automatically removed.
    if URL_PATTERN.search(sanitized):
        findings.append("URL detected; review required")

    return sanitized, list(set(findings))
