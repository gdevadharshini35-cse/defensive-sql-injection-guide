"""
input_validator.py - Defensive Server-Side Input Validation
Course: Value Added Course (VAC) in Cybersecurity

DEFENSIVE SECURITY PRINCIPLE:
"Never trust user input." 

Client-side validation provides a smooth user experience, but attackers can easily 
bypass browser validation using cURL, Postman, or Burp Suite. Therefore, strict 
SERVER-SIDE validation is mandatory.

Input validation is the first line of Defense-in-Depth, ensuring input conforms to 
expected format, length, and character sets before reaching business logic.
"""

import re
import html

# Allow-list regex pattern: Username must be alphanumeric, 3 to 30 characters
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")

# RFC-compliant email pattern
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

# Common SQL Injection payload signatures for educational detection & audit logging
SQLI_SIGNATURE_PATTERN = re.compile(
    r"(?i)('.*?(--|#|/\*)|union\s+select|select\s+.*\s+from|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
    r"or\s+['\"][^'\"]*['\"]\s*=\s*['\"][^'\"]*|waitfor\s+delay|sleep\s*\(|drop\s+table|"
    r"insert\s+into|delete\s+from|--|#|;)"
)


def is_valid_username(username: str) -> bool:
    """Validates if a username meets defensive alphanumeric criteria."""
    if not username:
        return False
    return bool(USERNAME_PATTERN.match(username.strip()))


def is_valid_email(email: str) -> bool:
    """Validates if an email address meets standard email format."""
    if not email:
        return False
    return bool(EMAIL_PATTERN.match(email.strip()))


def is_safe_length(text: str, min_len: int, max_len: int) -> bool:
    """Checks if input length is within safe bounds to prevent buffer/DoS issues."""
    if text is None:
        return False
    length = len(text.strip())
    return min_len <= length <= max_len


def contains_sqli_pattern(text: str) -> bool:
    """
    Educational detection helper: checks if an input contains classic SQL Injection signatures.
    NOTE: Parameterized queries remain the ONLY mathematical solution to SQLi.
    """
    if not text:
        return False
    return bool(SQLI_SIGNATURE_PATTERN.search(text))


def escape_html(text: str) -> str:
    """Sanitizes text for safe HTML rendering to prevent Cross-Site Scripting (XSS)."""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)
