
from output_scanner import scan_output

test_cases = [
    {
        "name": "Normal response",
        "input": "You can reset your password through the employee portal.",
        "should_redact": False,
        "should_flag_url": False,
    },
    {
        "name": "Database connection string",
        "input": "Database: postgresql://admin:secret123@localhost:5432/hr",
        "should_redact": True,
        "should_flag_url": False,
    },
    {
        "name": "API key",
        "input": "Admin API key: abcdef1234567890",
        "should_redact": True,
        "should_flag_url": False,
    },
    {
        "name": "Password",
        "input": "Password: Summer2024!",
        "should_redact": True,
        "should_flag_url": False,
    },
    {
        "name": "Synthetic canary",
        "input": "Canary: TC-DEMO-CANARY-7419",
        "should_redact": True,
        "should_flag_url": False,
    },
    {
        "name": "Internal project identifier",
        "input": "Project: ORCHID-TRAINING",
        "should_redact": True,
        "should_flag_url": False,
    },
    {
        "name": "URL detection",
        "input": "Visit https://example.com/help for assistance.",
        "should_redact": False,
        "should_flag_url": True,
    },
    {
        "name": "Internal handbook path",
        "input": "Handbook: /srv/techcorp/handbook.txt",
        "should_redact": True,
        "should_flag_url": False,
    },
    {
        "name": "Internal hostname",
        "input": "Server: hr-export.internal.techcorp.local",
        "should_redact": True,
        "should_flag_url": False,
    },
]

for index, test in enumerate(test_cases, start=1):
    sanitized, findings = scan_output(test["input"])

    was_redacted = "[REDACTED]" in sanitized
    url_was_flagged = any("URL detected" in item for item in findings)

    passed = (
        was_redacted == test["should_redact"]
        and url_was_flagged == test["should_flag_url"]
    )

    print(f"\nTest {index}: {test['name']}")
    print("Result:", "PASS" if passed else "FAIL")
    print("Sanitized:", sanitized)
    print("Findings:", findings)
