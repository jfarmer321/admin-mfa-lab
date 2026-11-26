"""Local-only admin authentication lab. No real accounts or network services."""
import argparse
import getpass
import hashlib
import hmac
import re
import secrets
import time

STEP = 30
DEMO_PASSWORD = "demo-only-password"


def hotp(secret, counter, digits=6):
    digest = hmac.digest(secret, counter.to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 10**digits:0{digits}d}"


class AdminLogin:
    """One fake account, with state kept only for the current process."""

    def __init__(self, secret, password=DEMO_PASSWORD):
        self.secret = secret
        self.salt = secrets.token_bytes(16)
        self.password_hash = self._password_hash(password)
        self.last_used_step = -1
        self.failures = 0
        self.retry_at = 0
        self.audit = []

    def _password_hash(self, password):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), self.salt, 600_000)

    def _record(self, now, result):
        self.audit.append({"time": int(now), "account": "demo-admin", "result": result})
        return result

    def login(self, password, code, *, now=None):
        now = time.time() if now is None else now
        if now < self.retry_at:
            return self._record(now, "cooldown")

        step = int(now) // STEP
        good_password = hmac.compare_digest(self._password_hash(password), self.password_hash)
        good_code = bool(re.fullmatch(r"[0-9]{6}", code)) and hmac.compare_digest(
            code, hotp(self.secret, step)
        )
        if good_password and good_code and step > self.last_used_step:
            self.last_used_step = step
            self.failures = 0
            return self._record(now, "allowed")

        self.failures += 1
        if self.failures == 3:
            self.retry_at = now + STEP
            self.failures = 0
        status = "replay" if good_password and good_code else "denied"
        return self._record(now, status)


def different_code(*codes):
    return next(f"{n:06d}" for n in range(len(codes) + 1) if f"{n:06d}" not in codes)


def walkthrough():
    # Public RFC 6238 test-vector seed, never a real account secret.
    seed = b"12345678901234567890"
    now = 1_234_567_890
    step = now // STEP
    current = hotp(seed, step)
    expired = hotp(seed, step - 1)
    wrong = different_code(current, expired)
    login = AdminLogin(seed)
    cases = [
        ("Wrong password, valid code", "wrong-password", current, now, "denied"),
        ("Expired code", DEMO_PASSWORD, expired, now, "denied"),
        ("Valid password and code", DEMO_PASSWORD, current, now, "allowed"),
        ("Same code used a second time", DEMO_PASSWORD, current, now, "replay"),
        ("Incorrect code", DEMO_PASSWORD, wrong, now, "denied"),
        ("Third failure starts cooldown", DEMO_PASSWORD, wrong, now, "denied"),
        ("Request during cooldown", DEMO_PASSWORD, current, now, "cooldown"),
        ("Fresh code after cooldown", DEMO_PASSWORD, hotp(seed, step + 1), now + STEP, "allowed"),
    ]
    print("ADMIN MFA LAB | simulated sign-in evidence")
    for label, password, code, when, expected in cases:
        result = login.login(password, code, now=when)
        print(f"{label:<34} {result}")
        if result != expected:
            raise RuntimeError(f"{label}: expected {expected}, got {result}")
    print(f"\nAll {len(cases)} scenarios matched expected results.")


def interactive():
    seed = secrets.token_bytes(20)
    login = AdminLogin(seed)
    print("Local MFA lab. Account: demo-admin. Password: demo-only-password.")
    print("Use only the fake credentials shown above. Press Ctrl+C to quit.")
    while True:
        now = time.time()
        print(f"Simulated authenticator: {hotp(seed, int(now) // STEP)} "
              f"({STEP - int(now) % STEP}s left)")
        password = getpass.getpass("Fake password: ")
        code = input("Six-digit code (Enter for a fresh display): ").strip()
        if code:
            result = login.login(password, code)
            print("Access granted." if result == "allowed" else "Access denied.")
            print(f"Lab audit: {login.audit[-1]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interactive", action="store_true", help="try the mock login manually")
    args = parser.parse_args()
    try:
        interactive() if args.interactive else walkthrough()
    except (KeyboardInterrupt, EOFError):
        print("\nLab closed.")
