from __future__ import annotations
import base64
import hashlib
import hmac
import struct
import time
from typing import Any

REPORT_KIND = "otpburn"
SIGN_VERSION = "v1"

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "otpburn", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

def _report(decision: str, reason_codes: list[str], notes: list[str]) -> dict:
    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "kind": REPORT_KIND,
        "notes": notes,
    }

def _deny(reason: str, note: str) -> dict:
    return _report("deny", [reason], [note])

def _hotp(secret: bytes, counter: int, digits: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)

def _sign_line(kid: str, account: str, counter: int, code: str) -> str:
    return f"{SIGN_VERSION}|{kid}|{account}|{counter}|{code}"

def _expected_sig(secret: bytes, line: str) -> str:
    digest = hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Verify a TOTP admission object per docs/admit-rules.md.

    On allow the consumed counter is burned into ``store`` (mutated in
    place); deny paths never touch the store.
    """
    if now_unix is None:
        now_unix = int(time.time())

    if not isinstance(obj, dict):
        return _deny("malformed_input", "input must be a JSON object")
    kid = obj.get("kid")
    account = obj.get("account")
    counter = obj.get("counter")
    code = obj.get("code")
    sig = obj.get("sig")
    if (not isinstance(kid, str) or not kid
            or not isinstance(account, str) or not account
            or not isinstance(counter, int) or isinstance(counter, bool) or counter < 0
            or not isinstance(code, str) or not code
            or not isinstance(sig, str) or not sig):
        return _deny("malformed_input", "kid/account/counter/code/sig are required")

    ring = keys.get("keys", keys) if isinstance(keys, dict) else {}
    key = ring.get(kid)
    if not isinstance(key, dict):
        return _deny("unknown_kid", f"kid {kid!r} is not in the key ring")
    try:
        secret = bytes.fromhex(str(key.get("secret", "")))
    except ValueError:
        secret = b""
    if not secret:
        return _deny("unknown_kid", f"kid {kid!r} has no usable secret")

    if key.get("status") == "revoked":
        return _deny("key_revoked", f"kid {kid!r} is revoked")
    not_before = key.get("not_before")
    not_after = key.get("not_after")
    if isinstance(not_before, int) and now_unix < not_before:
        return _deny("epoch_out_of_range", f"kid {kid!r} not valid before {not_before}")
    if isinstance(not_after, int) and now_unix > not_after:
        return _deny("epoch_out_of_range", f"kid {kid!r} not valid after {not_after}")

    allow_accounts = policy.get("allow_accounts", []) if isinstance(policy, dict) else []
    if account not in allow_accounts:
        return _deny("account_not_allowed", f"account {account!r} is not in allow_accounts")

    line = _sign_line(kid, account, counter, code)
    if not hmac.compare_digest(_expected_sig(secret, line), sig):
        return _deny("bad_signature", "signature does not match the signing input")

    step = int(policy.get("step", 30))
    window = int(policy.get("window", 1))
    digits = int(policy.get("digits", 6))
    t0 = int(policy.get("t0", 0))
    if step <= 0 or window < 0 or digits <= 0:
        raise ValueError("policy step/window/digits are invalid")
    current_step = (now_unix - t0) // step
    if abs(counter - current_step) > window:
        return _deny("window_exceeded", "counter is outside the allowed window")

    if not isinstance(store, dict):
        raise ValueError("store must be an object with an items object")
    items = store.get("items", {})
    if not isinstance(items, dict):
        raise ValueError("store items must be an object")
    burn_key = f"{kid}:{counter}"
    if burn_key in items:
        return _deny("replay", "counter was already consumed")

    if not hmac.compare_digest(_hotp(secret, counter, digits), code):
        return _deny("code_mismatch", "code does not match the expected TOTP value")

    store.setdefault("items", {})[burn_key] = {"ts": now_unix, "account": account}
    return _report("allow", [], [])
