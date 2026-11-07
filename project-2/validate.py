
import re
import base64
import binascii


MAX_INPUT_LENGTH = 500


# Common prompt-injection patterns.
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"reveal\s+(your\s+)?(full\s+)?system\s+prompt",
    r"(print|show|display|output)\s+(your\s+)?(full\s+)?system\s+prompt",
    r"reveal\s+(the\s+)?(admin\s+)?api\s+key",
    r"act\s+as\s+(dan|an?\s+unrestricted)",
    r"no\s+restrictions",
    r"bypass\s+(the\s+)?(security|safety|authentication)\s+(filter|controls?|checks?)",
    r"begin\s+developer\s+message",
    r"treat\s+.*as\s+a\s+trusted\s+(developer|system)\s+instruction",
]

COMPILED_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in INJECTION_PATTERNS
]


def contains_injection(text):
    """Check text for common prompt-injection instructions."""
    return any(pattern.search(text) for pattern in COMPILED_PATTERNS)


def contains_encoded_injection(text):
    """Decode Base64-looking text and inspect it without executing it."""
    candidates = re.findall(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])",
        text
    )

    for candidate in candidates:
        try:
            decoded = base64.b64decode(
                candidate,
                validate=True
            ).decode("utf-8")

            if contains_injection(decoded):
                return True

        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

    return False


def validate_input(message):
    """
    Returns:
        (True, "Input accepted") when the input passes.
        (False, reason) when the input is rejected.
    """

    if not isinstance(message, str):
        return False, "Input must be a string."

    if not message.strip():
        return False, "Input cannot be empty."

    if len(message) > MAX_INPUT_LENGTH:
        return False, f"Input exceeds the {MAX_INPUT_LENGTH}-character limit."

    if contains_injection(message):
        return False, "Potential prompt injection detected."

    if contains_encoded_injection(message):
        return False, "Encoded prompt injection detected."

    return True, "Input accepted."
