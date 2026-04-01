import getpass
import sys


DIVIDER = "-" * 52


def header(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


def section(title: str) -> None:
    print(f"\n-- {title} --")


def ok(msg: str) -> None:
    print(f"ok: {msg}")


def err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"warning: {msg}")


def prompt(label: str) -> str:
    return input(f"{label}: ").strip()


def prompt_int(label: str, default: int) -> int:
    raw = input(f"{label} (default {default}): ").strip()
    return int(raw) if raw.isdigit() else default


def secret(label: str) -> str:
    """Read a password without echoing. Falls back to plain input if no tty."""
    try:
        return getpass.getpass(f"{label}: ")
    except Exception:
        print(f"{label}: ", end="", flush=True)
        return input()


def confirm(question: str) -> bool:
    raw = input(f"{question} [y/n]: ").strip().lower()
    return raw == "y"


def confirm_destructive(question: str) -> bool:
    raw = input(f"{question} (type 'yes' to confirm): ").strip().lower()
    return raw == "yes"


def pick_from_list(items: list, label: str = "Select") -> int:
    """
    Print a numbered list and return the 0-based index of the user's choice.
    Returns -1 if the input is invalid.
    """
    for i, item in enumerate(items, 1):
        print(f"  {i}. {item}")
    raw = input(f"\n{label}: ").strip()
    if raw.isdigit() and 1 <= int(raw) <= len(items):
        return int(raw) - 1
    return -1
