import math
import re
import secrets
import string


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    alphabet = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]

    if use_uppercase:
        alphabet += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        alphabet += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        alphabet += symbols
        required.append(secrets.choice(symbols))

    length = max(length, len(required))
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    password_chars = required + remaining
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def _pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
        pool += 32
    return pool or 1


def entropy_bits(password: str) -> float:
    pool = _pool_size(password)
    return len(password) * math.log2(pool)


def check_strength(password: str) -> dict:
    bits = entropy_bits(password)
    issues = []

    if len(password) < 8:
        issues.append("too short, minimum 8 characters")
    if not re.search(r"[a-z]", password):
        issues.append("no lowercase letters")
    if not re.search(r"[A-Z]", password):
        issues.append("no uppercase letters")
    if not re.search(r"\d", password):
        issues.append("no digits")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
        issues.append("no special characters")

    if bits >= 80:
        label = "Very Strong"
    elif bits >= 60:
        label = "Strong"
    elif bits >= 40:
        label = "Fair"
    elif bits >= 28:
        label = "Weak"
    else:
        label = "Very Weak"

    return {"label": label, "entropy": round(bits, 1), "issues": issues}
