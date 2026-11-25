#!/usr/bin/env python3
"""
End-to-end test of the ACR/AMR POC against the running docker-compose stack.

Drives real browser-style logins (HTML forms, cookies, mTLS client certificates)
through Keycloak's browser flow with Authorization Code + PKCE, exchanges the code
and asserts the `acr`, `amr` and `x509_issuer` claims in both the ID token and the
access token (plus the introspection endpoint).

Standard library only. Usage:
    python3 scripts/e2e_test.py              # all scenarios
    python3 scripts/e2e_test.py -k x509      # scenarios whose name contains "x509"

Passkey (WebAuthn) cannot be automated here without a virtual authenticator; it is
covered by scripts/e2e_passkey_test.py (software authenticator) and manually in a browser.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS = os.path.join(ROOT, "certs")
BASE = os.environ.get("KC_BASE_URL", "https://localhost:8443")
REALM = os.environ.get("KC_REALM", "acr-poc")
CLIENT_ID = "bruno"
REDIRECT_URI = "http://localhost:8081/callback"
API_CLIENT_ID = "poc-api"
API_CLIENT_SECRET = os.environ.get("POC_API_SECRET", "poc-api-secret-change-me")
USERNAME, PASSWORD = "testuser", os.environ.get("TESTUSER_PASSWORD", "Test1234!")

ISSUER_STANDARD = "CN=Test CA Standard,O=Example Org,C=SE"
ISSUER_HIGH = "CN=Test CA High Trust,O=Example Org,C=SE"

OIDC = f"{BASE}/realms/{REALM}/protocol/openid-connect"


# --------------------------------------------------------------------------- HTML


class FormParser(HTMLParser):
    """Collects <form> elements with their inputs/buttons, and the page's visible text.

    Each form also gets a "label": the visible text that follows it up to the next form.
    Keycloak's "select authenticator" page renders one hidden-input form per option and
    puts the option's title in a sibling element, so this is how options are told apart.
    """

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._form: dict | None = None
        self._button: dict | None = None
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {"id": a.get("id"), "action": a.get("action"), "fields": {}, "buttons": [], "label": ""}
            self.forms.append(self._form)
        elif self._form is not None and tag == "input" and a.get("name"):
            self._form["fields"][a["name"]] = a.get("value", "")
        elif self._form is not None and tag == "button":
            self._button = {"name": a.get("name"), "value": a.get("value", ""), "text": ""}
            self._form["buttons"].append(self._button)

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "button":
            self._button = None

    def handle_data(self, data):
        if self._button is not None:
            self._button["text"] += data
        if data.strip():
            self.text.append(data.strip())
            if self._form is None and self.forms:
                self.forms[-1]["label"] += " " + data.strip()


def parse(html: str) -> FormParser:
    p = FormParser()
    p.feed(html)
    return p


def form_by_id(page: FormParser, form_id: str) -> dict | None:
    return next((f for f in page.forms if f["id"] == form_id), None)


# --------------------------------------------------------------------------- HTTP


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - handle redirects manually
        return None


@dataclass
class Browser:
    """A cookie-keeping HTTP client that may present a client certificate."""

    cert: str | None = None
    jar: http.cookiejar.CookieJar = field(default_factory=http.cookiejar.CookieJar)

    def opener(self) -> urllib.request.OpenerDirector:
        ctx = ssl.create_default_context(cafile=os.path.join(CERTS, "ca-standard.crt"))
        if self.cert:
            ctx.load_cert_chain(os.path.join(CERTS, f"{self.cert}.crt"), os.path.join(CERTS, f"{self.cert}.key"))
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, url: str, data: dict | None = None) -> tuple[int, dict, str]:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body)
        try:
            with self.opener().open(req, timeout=20) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:  # 3xx (no redirect handler) and 4xx/5xx land here
            return e.code, dict(e.headers), e.read().decode(errors="replace")


# --------------------------------------------------------------------------- OIDC helpers


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


@dataclass
class LoginResult:
    code: str | None = None
    verifier: str = ""
    pages: list[str] = field(default_factory=list)  # ids of the forms we went through
    final_status: int = 0
    final_html: str = ""


def login(browser: Browser, *, acr_values: str | None = None, claims: dict | None = None,
          use_password: bool = True, stop_at_passkey: bool = False, prefer: str = "password", max_steps: int = 12,
          extra_params: dict | None = None, handlers: dict | None = None) -> LoginResult:
    """Runs the browser flow until Keycloak redirects back with a code (or shows an error).

    Handles: X.509 confirmation page, passkey page (-> "Try another way"), authenticator
    selection page (-> password) and the username/password form.

    ``prefer`` ("password" or "passkey") selects the option on the "Try another way" page;
    with "passkey" the password form is skipped via "Try another way".

    ``handlers`` maps a form id to ``fn(browser, html, form) -> (status, headers, html)``
    and takes precedence over the built-in handling (used by the passkey test to answer
    WebAuthn challenges). ``extra_params`` are added to the authorization request.
    """
    verifier = b64url(secrets.token_bytes(32))
    params = {
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "response_type": "code", "scope": "openid",
        "state": secrets.token_hex(8), "nonce": secrets.token_hex(8),
        "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
    }
    if acr_values:
        params["acr_values"] = acr_values
    if claims:
        params["claims"] = json.dumps(claims)
    params.update(extra_params or {})

    res = LoginResult(verifier=verifier)
    status, headers, html = browser.request(f"{OIDC}/auth?{urllib.parse.urlencode(params)}")

    for _ in range(max_steps):
        location = headers.get("Location") or headers.get("location")
        if status in (302, 303) and location:
            if location.startswith(REDIRECT_URI):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
                if "error" in q:
                    res.final_html = f"redirect error: {q}"
                    res.final_status = status
                    return res
                assert q["state"][0] == params["state"], "state mismatch"
                res.code = q["code"][0]
                return res
            status, headers, html = browser.request(urllib.parse.urljoin(BASE, location))
            continue

        page = parse(html)
        custom = next(((fid, fn) for fid, fn in (handlers or {}).items() if form_by_id(page, fid)), None)
        if custom:
            res.pages.append(custom[0])
            status, headers, html = custom[1](browser, html, form_by_id(page, custom[0]))
        elif f := form_by_id(page, "kc-x509-login-info"):
            res.pages.append("x509-confirm")
            # Submit "Sign in" (not "Ignore", which would skip the certificate).
            status, headers, html = browser.request(f["action"], {"login": "Sign in"})
        elif form_by_id(page, "webauth"):
            res.pages.append("passkey")
            if stop_at_passkey:
                break
            f = form_by_id(page, "kc-select-try-another-way-form")
            assert f, "passkey page without 'Try another way'"
            status, headers, html = browser.request(f["action"], {"tryAnotherWay": "on"})
        elif form_by_id(page, "kc-select-credential-form"):
            res.pages.append("select-authenticator")
            # One form per option; pick the one whose label mentions the preferred method.
            options = [f for f in page.forms if f["id"] == "kc-select-credential-form"]
            pick = next((f for f in options if prefer in f["label"].lower()), None)
            if pick is None:
                raise AssertionError(f"no {prefer} option on selection page: {[o['label'][:40] for o in options]}")
            status, headers, html = browser.request(pick["action"], pick["fields"])
        elif form_by_id(page, "kc-form-login") and prefer == "passkey" and "select-authenticator" not in res.pages:
            res.pages.append("password-form-skipped")
            f = form_by_id(page, "kc-select-try-another-way-form")
            status, headers, html = browser.request(f["action"], {"tryAnotherWay": "on"})
        elif (f := form_by_id(page, "kc-form-login")) is not None and use_password:
            res.pages.append("password")
            status, headers, html = browser.request(
                f["action"], {"username": USERNAME, "password": PASSWORD, "credentialId": ""})
        else:
            break

    res.final_status, res.final_html = status, html
    return res


def exchange(code: str, verifier: str) -> dict:
    status, _, body = Browser().request(f"{OIDC}/token", {
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID, "code_verifier": verifier,
    })
    assert status == 200, f"token endpoint returned {status}: {body}"
    return json.loads(body)


def introspect(token: str) -> dict:
    status, _, body = Browser().request(f"{OIDC}/token/introspect", {
        "token": token, "client_id": API_CLIENT_ID, "client_secret": API_CLIENT_SECRET,
    })
    assert status == 200, f"introspection returned {status}: {body}"
    return json.loads(body)


def assert_claims(tokens: dict, *, acr: str, amr: set[str], issuer: str | None) -> None:
    """Asserts acr/amr/x509_issuer in ID token, access token and introspection."""
    for kind in ("id_token", "access_token"):
        c = jwt_claims(tokens[kind])
        assert c.get("acr") == acr, f"{kind}: acr={c.get('acr')!r}, expected {acr!r}"
        assert set(c.get("amr", [])) == amr, f"{kind}: amr={c.get('amr')!r}, expected {sorted(amr)}"
        assert c.get("x509_issuer") == issuer, f"{kind}: x509_issuer={c.get('x509_issuer')!r}, expected {issuer!r}"
    i = introspect(tokens["access_token"])
    assert i.get("active") is True and i.get("acr") == acr, f"introspection: {i}"


def summary(tokens: dict) -> str:
    c = jwt_claims(tokens["id_token"])
    return f"acr={c.get('acr')} amr={c.get('amr')} x509_issuer={c.get('x509_issuer')}"


# --------------------------------------------------------------------------- scenarios


def sc_password() -> str:
    r = login(Browser())
    assert r.code, f"no code; pages={r.pages} status={r.final_status}"
    assert r.pages[-1] == "password", r.pages
    t = exchange(r.code, r.verifier)
    assert_claims(t, acr="loa1", amr={"pwd"}, issuer=None)
    return summary(t)


def sc_x509_standard() -> str:
    r = login(Browser(cert="testuser-standard"))
    assert r.code and r.pages == ["x509-confirm"], f"pages={r.pages} status={r.final_status}"
    t = exchange(r.code, r.verifier)
    assert_claims(t, acr="loa2", amr={"x509"}, issuer=ISSUER_STANDARD)
    return summary(t)


def sc_x509_high() -> str:
    r = login(Browser(cert="testuser-high"))
    assert r.code and r.pages == ["x509-confirm"], f"pages={r.pages} status={r.final_status}"
    t = exchange(r.code, r.verifier)
    assert_claims(t, acr="loa3", amr={"x509"}, issuer=ISSUER_HIGH)
    return summary(t)


def sc_x509_unmapped_fails_closed() -> str:
    r = login(Browser(cert="testuser-unmapped"))
    assert r.code is None, "unmapped CA must NOT yield an authorization code"
    assert r.final_status == 401, f"expected 401 error page, got {r.final_status}"
    assert "not approved for login" in r.final_html, "expected the fail-closed error message"
    return f"rejected with HTTP {r.final_status} after pages={r.pages}"


def sc_sso_keeps_loa3() -> str:
    b = Browser(cert="testuser-high")
    r = login(b)
    assert r.code
    exchange(r.code, r.verifier)
    # Second authorization in the same browser session, now WITHOUT a client certificate.
    sso = Browser(cert=None, jar=b.jar)
    r2 = login(sso)
    assert r2.code and r2.pages == [], f"expected silent SSO, got pages={r2.pages}"
    t = exchange(r2.code, r2.verifier)
    assert_claims(t, acr="loa3", amr={"x509"}, issuer=ISSUER_HIGH)
    return "SSO: " + summary(t)


def sc_stepup_pwd_to_loa3() -> str:
    b = Browser()
    r = login(b)
    assert r.code
    t1 = exchange(r.code, r.verifier)
    assert jwt_claims(t1["id_token"])["acr"] == "loa1"
    # Same session, now present the High Trust certificate and ask for loa3.
    stepped = Browser(cert="testuser-high", jar=b.jar)
    r2 = login(stepped, acr_values="loa3")
    assert r2.code and r2.pages == ["x509-confirm"], f"pages={r2.pages}"
    t2 = exchange(r2.code, r2.verifier)
    assert_claims(t2, acr="loa3", amr={"pwd", "x509"}, issuer=ISSUER_HIGH)
    return "loa1 -> " + summary(t2)


def sc_sso_without_stepup_keeps_loa1() -> str:
    b = Browser()
    r = login(b)
    assert r.code
    exchange(r.code, r.verifier)
    r2 = login(Browser(jar=b.jar), acr_values="loa1")
    assert r2.code and r2.pages == [], f"pages={r2.pages}"
    t = exchange(r2.code, r2.verifier)
    assert_claims(t, acr="loa1", amr={"pwd"}, issuer=None)
    return "SSO: " + summary(t)


def sc_stepup_loa2_without_passkey_denied() -> str:
    """SSO at loa1, client asks for loa2, user has no passkey and no certificate.

    The cookie identifies the user, so the passkey step runs for *that* user; since no
    passkey is registered it fails, and Keycloak must NOT fall back to issuing a loa1 code.
    """
    b = Browser()
    r = login(b)
    assert r.code
    exchange(r.code, r.verifier)
    r2 = login(Browser(jar=b.jar), acr_values="loa2", stop_at_passkey=True)
    assert r2.code is None, f"step-up to loa2 must not silently return a code (pages={r2.pages})"
    assert r2.final_status >= 400, f"expected an error page, got HTTP {r2.final_status}"
    return f"no passkey registered -> no code, HTTP {r2.final_status}"


def sc_essential_acr_not_met_is_rejected() -> str:
    r = login(Browser(), claims=ESSENTIAL_LOA3)
    assert r.code is None, "essential loa3 must not be satisfied by a password login"
    return f"password login with essential acr=loa3 rejected (HTTP {r.final_status}, pages={r.pages})"


ESSENTIAL_LOA3 = {"id_token": {"acr": {"essential": True, "values": ["loa3"]}}}


def sc_essential_loa3_standard_cert_rejected() -> str:
    """Essential loa3 must not be satisfied by a Standard-CA (loa2) certificate.

    Regression test: on the X.509 path no LoA condition runs, so the SPI itself must enforce it.
    """
    r = login(Browser(cert="testuser-standard"), claims=ESSENTIAL_LOA3)
    assert r.code is None, "essential loa3 satisfied by a loa2 certificate"
    return f"Standard cert + essential loa3 rejected (HTTP {r.final_status})"


def sc_essential_loa3_high_cert_accepted() -> str:
    r = login(Browser(cert="testuser-high"), claims=ESSENTIAL_LOA3)
    assert r.code, f"High Trust cert must satisfy essential loa3 (pages={r.pages}, status={r.final_status})"
    t = exchange(r.code, r.verifier)
    assert_claims(t, acr="loa3", amr={"x509"}, issuer=ISSUER_HIGH)
    return summary(t)


def sc_essential_loa3_stepup_standard_rejected() -> str:
    b = Browser()
    r = login(b)
    assert r.code
    exchange(r.code, r.verifier)
    r2 = login(Browser(cert="testuser-standard", jar=b.jar), claims=ESSENTIAL_LOA3)
    assert r2.code is None, "step-up with a loa2 certificate satisfied an essential loa3 request"
    return f"pwd session + Standard cert + essential loa3 rejected (HTTP {r2.final_status})"


def sc_acr_values_is_voluntary() -> str:
    """acr_values is a *voluntary* request: a password login still gets a code, with acr=loa1.

    This is why applications must always check the acr claim themselves.
    """
    r = login(Browser(), acr_values="loa3")
    assert r.code, f"expected a code for a non-essential acr request (pages={r.pages})"
    t = exchange(r.code, r.verifier)
    assert_claims(t, acr="loa1", amr={"pwd"}, issuer=None)
    return "acr_values=loa3 + password -> " + summary(t) + " (app must reject)"


SCENARIOS = [
    ("password", sc_password),
    ("x509-standard", sc_x509_standard),
    ("x509-high", sc_x509_high),
    ("x509-unmapped-fails-closed", sc_x509_unmapped_fails_closed),
    ("sso-keeps-loa3", sc_sso_keeps_loa3),
    ("sso-keeps-loa1", sc_sso_without_stepup_keeps_loa1),
    ("stepup-pwd-to-loa3-x509", sc_stepup_pwd_to_loa3),
    ("stepup-loa2-without-passkey-denied", sc_stepup_loa2_without_passkey_denied),
    ("essential-acr-not-met-rejected", sc_essential_acr_not_met_is_rejected),
    ("essential-loa3-standard-cert-rejected", sc_essential_loa3_standard_cert_rejected),
    ("essential-loa3-high-cert-accepted", sc_essential_loa3_high_cert_accepted),
    ("essential-loa3-stepup-std-rejected", sc_essential_loa3_stepup_standard_rejected),
    ("acr-values-is-voluntary", sc_acr_values_is_voluntary),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-k", help="only run scenarios whose name contains this string")
    ap.add_argument("--issue-code", metavar="METHOD",
                    help="do not run tests; log in with METHOD (password | testuser-standard | testuser-high) and "
                         "print {code, verifier} as JSON (used by scripts/validate-bruno.sh)")
    ap.add_argument("--acr-values", help="acr_values for --issue-code")
    args = ap.parse_args()

    if args.issue_code:
        cert = None if args.issue_code == "password" else args.issue_code
        r = login(Browser(cert=cert), acr_values=args.acr_values)
        if not r.code:
            print(f"login failed: pages={r.pages} status={r.final_status}", file=sys.stderr)
            return 1
        print(json.dumps({"code": r.code, "verifier": r.verifier}))
        return 0

    failed = 0
    for name, fn in SCENARIOS:
        if args.k and args.k not in name:
            continue
        try:
            print(f"PASS  {name:34s} {fn()}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {name:34s} {e}")
        except Exception as e:  # noqa: BLE001 - report and continue
            failed += 1
            print(f"ERROR {name:34s} {type(e).__name__}: {e}")
    print(f"\n{'OK' if not failed else 'FAILED'}: {failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
