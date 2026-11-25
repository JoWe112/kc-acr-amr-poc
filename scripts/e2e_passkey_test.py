#!/usr/bin/env python3
"""
End-to-end passkey (WebAuthn) test using a software authenticator.

Emulates a FIDO2 platform authenticator (ECDSA P-256, "none" attestation, user
verification flag set) so the Passkey branch of the browser flow can be tested
without a browser:

  1. Clean up: remove any passkeys of testuser (admin REST API).
  2. Register a passkey through Keycloak's own required action
     (password login + kc_action=webauthn-register-passwordless).
  3. Fresh login with the passkey only        -> acr=loa2, amr=[hwk]
  4. Password session + acr_values=loa2       -> passkey step-up, acr=loa2, amr=[pwd,hwk]
  5. Clean up again so scripts/e2e_test.py keeps its "no passkey" precondition.

Requires the `cryptography` package. Run via scripts/run-e2e.sh (installs it in a
throw-away container) or: pip install cryptography && python3 scripts/e2e_passkey_test.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import struct
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_test as e  # noqa: E402  (shared HTTP/OIDC helpers)

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:  # pragma: no cover
    print("SKIP  passkey tests: the 'cryptography' package is not installed (use scripts/run-e2e.sh)")
    sys.exit(0)

RP_ID = "localhost"
ORIGIN = e.BASE  # https://localhost:8443
ADMIN_USER = os.environ.get("KC_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "admin")


# --------------------------------------------------------------------------- minimal CBOR encoder


def cbor(obj) -> bytes:
    """Encodes the subset of CBOR needed for WebAuthn (ints, bytes, text, maps)."""

    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        if n < 0x100:
            return bytes([major << 5 | 24, n])
        if n < 0x10000:
            return bytes([major << 5 | 25]) + struct.pack(">H", n)
        return bytes([major << 5 | 26]) + struct.pack(">I", n)

    if isinstance(obj, bool):
        raise TypeError("bool not supported")
    if isinstance(obj, int):
        return head(0, obj) if obj >= 0 else head(1, -1 - obj)
    if isinstance(obj, bytes):
        return head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode()
        return head(3, len(b)) + b
    if isinstance(obj, dict):
        return head(5, len(obj)) + b"".join(cbor(k) + cbor(v) for k, v in obj.items())
    raise TypeError(type(obj))


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- software authenticator


class SoftAuthenticator:
    """A single resident ES256 credential."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.user_handle: bytes | None = None
        self.counter = 0

    def _cose_public_key(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    @staticmethod
    def _client_data(kind: str, challenge: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": False},
                          separators=(",", ":")).encode()

    def create(self, challenge: str, user_id_b64: str) -> dict:
        """navigator.credentials.create() -> form fields expected by Keycloak's register form."""
        self.user_handle = b64url_decode(user_id_b64)
        client_data = self._client_data("webauthn.create", challenge)
        flags = 0x01 | 0x04 | 0x40  # UP | UV | AT
        auth_data = (hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
                     + bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id
                     + self._cose_public_key())
        attestation = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "clientDataJSON": e.b64url(client_data),
            "attestationObject": e.b64url(attestation),
            "publicKeyCredentialId": e.b64url(self.credential_id),
            "authenticatorLabel": "e2e soft authenticator",
            "transports": "internal",
            "authenticatorAttachment": "platform",
            "error": "",
        }

    def get(self, challenge: str) -> dict:
        """navigator.credentials.get() -> form fields expected by Keycloak's webauth form."""
        self.counter += 1
        client_data = self._client_data("webauthn.get", challenge)
        auth_data = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x01 | 0x04]) + struct.pack(">I", self.counter)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "clientDataJSON": e.b64url(client_data),
            "authenticatorData": e.b64url(auth_data),
            "signature": e.b64url(signature),
            "credentialId": e.b64url(self.credential_id),
            "userHandle": e.b64url(self.user_handle or b""),
            "error": "",
        }


def js_value(html: str, name: str) -> str:
    m = re.search(name + r'\s*:\s*"([^"]*)"', html)
    assert m, f"'{name}' not found in WebAuthn page"
    return m.group(1)


# --------------------------------------------------------------------------- admin helpers


def admin_token() -> str:
    status, _, body = e.Browser().request(f"{e.BASE}/realms/master/protocol/openid-connect/token", {
        "grant_type": "password", "client_id": "admin-cli", "username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert status == 200, f"admin login failed: {status}"
    return json.loads(body)["access_token"]


def admin_call(method: str, path: str) -> tuple[int, str]:
    import ssl
    import urllib.request
    ctx = ssl.create_default_context(cafile=os.path.join(e.CERTS, "ca-standard.crt"))
    req = urllib.request.Request(f"{e.BASE}/admin/realms/{e.REALM}{path}", method=method,
                                 headers={"Authorization": f"Bearer {admin_token()}"})
    with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
        return r.status, r.read().decode()


def remove_passkeys() -> int:
    _, users = admin_call("GET", f"/users?username={e.USERNAME}&exact=true")
    uid = json.loads(users)[0]["id"]
    _, creds = admin_call("GET", f"/users/{uid}/credentials")
    removed = 0
    for c in json.loads(creds):
        if c["type"].startswith("webauthn"):
            admin_call("DELETE", f"/users/{uid}/credentials/{c['id']}")
            removed += 1
    return removed


# --------------------------------------------------------------------------- scenarios


def main() -> int:
    auth = SoftAuthenticator()

    def on_register(browser, html, form):
        return browser.request(form["action"], auth.create(js_value(html, "challenge"), js_value(html, "userid")))

    def on_passkey(browser, html, form):
        return browser.request(form["action"], auth.get(js_value(html, "challenge")))

    failed = 0

    def run(name, fn):
        nonlocal failed
        try:
            print(f"PASS  {name:34s} {fn()}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL  {name:34s} {ex}")

    remove_passkeys()

    def register():
        # Password login + Keycloak's "register passkey" required action (kc_action).
        r = e.login(e.Browser(), extra_params={"kc_action": "webauthn-register-passwordless"},
                    handlers={"register": on_register})
        assert r.code and "register" in r.pages, f"registration failed: pages={r.pages} status={r.final_status}"
        return "passkey registered via required action"

    def passkey_login():
        # Keycloak shows the password form first; "Try another way" -> Passkey.
        r = e.login(e.Browser(), prefer="passkey", handlers={"webauth": on_passkey})
        assert r.code and r.pages[-1] == "webauth" and "password" not in r.pages, \
            f"pages={r.pages} status={r.final_status}"
        t = e.exchange(r.code, r.verifier)
        e.assert_claims(t, acr="loa2", amr={"hwk"}, issuer=None)
        return e.summary(t)

    def stepup_pwd_to_loa2():
        b = e.Browser()
        r = e.login(b)  # password
        assert r.code
        assert e.jwt_claims(e.exchange(r.code, r.verifier)["id_token"])["acr"] == "loa1"
        r2 = e.login(e.Browser(jar=b.jar), acr_values="loa2", handlers={"webauth": on_passkey})
        assert r2.code and r2.pages == ["webauth"], f"pages={r2.pages} status={r2.final_status}"
        t = e.exchange(r2.code, r2.verifier)
        e.assert_claims(t, acr="loa2", amr={"pwd", "hwk"}, issuer=None)
        return "loa1 -> " + e.summary(t)

    try:
        run("passkey-register", register)
        run("passkey-login", passkey_login)
        run("stepup-pwd-to-loa2-passkey", stepup_pwd_to_loa2)
    finally:
        print(f"      cleanup: removed {remove_passkeys()} passkey credential(s)")

    print(f"\n{'OK' if not failed else 'FAILED'}: {failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
