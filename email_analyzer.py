"""
Phishing email analyser for .eml files.

Reads a saved email (in Outlook: File > Save As > .msg won't work - forward as attachment
or use "Show original" in Gmail and download as .eml) and reports:

  * Authentication   SPF / DKIM / DMARC results from Authentication-Results
  * Sender checks    From vs Reply-To vs Return-Path, display-name impersonation
  * Routing          the Received chain (hops, first external IP)
  * Links            every URL, mismatched link text, look-alike and risky domains
  * Attachments      name, type, size, SHA-256, risky extensions and double extensions
  * Language         urgency, threats and credential requests
  * Verdict          weighted score -> CLEAN / SUSPICIOUS / MALICIOUS, plus a Markdown report

Nothing is opened or visited. Attachments are hashed, never executed.

Usage:
    python src/email_analyzer.py samples/02-credential-phish.eml
    python src/email_analyzer.py samples/ --report reports/
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

BRANDS = ["microsoft", "office365", "outlook", "paypal", "apple", "google", "amazon", "netflix",
          "commbank", "westpac", "anz", "nab", "auspost", "ato", "mygov", "docusign", "dhl", "linkedin"]
RISKY_TLDS = {"top", "xyz", "click", "zip", "mov", "work", "loan", "gq", "tk", "ml", "cf", "support", "rest"}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd", ".ps1",
                    ".iso", ".img", ".lnk", ".one", ".xlsm", ".docm", ".pptm", ".jar", ".msi", ".html", ".htm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz"}
URGENCY = [r"\burgent\b", r"immediate(ly)?", r"within \d+ hours", r"suspend(ed)?", r"act now",
           r"final (notice|warning)", r"overdue", r"today", r"permanent(ly)?", r"locked"]
CREDENTIAL = [r"verify (your )?(password|account|identity)", r"confirm (your )?(password|details)",
              r"sign[ -]?in", r"log[ -]?in", r"enable (content|macros|editing)", r"update (your )?payment"]
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


@dataclass
class Finding:
    category: str
    severity: str  # info / low / medium / high
    detail: str
    points: int = 0


@dataclass
class Report:
    file: str
    subject: str = ""
    from_addr: str = ""
    findings: list[Finding] = field(default_factory=list)
    urls: list[dict] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    hops: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.points for f in self.findings)

    @property
    def verdict(self) -> str:
        if self.score >= 8:
            return "MALICIOUS"
        if self.score >= 4:
            return "SUSPICIOUS"
        return "CLEAN"

    def add(self, category: str, severity: str, detail: str, points: int) -> None:
        self.findings.append(Finding(category, severity, detail, points))


class LinkExtractor(HTMLParser):
    """Collect (href, visible text) pairs from HTML."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(address: str) -> str:
    return parseaddr(address)[1].rpartition("@")[2].lower().strip(">")


def base_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 3 and parts[-2] in {"com", "gov", "org", "net", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def load(path: Path) -> EmailMessage:
    with path.open("rb") as handle:
        return BytesParser(policy=policy.default).parse(handle)


# ------------------------------------------------------------------ checks ---
def check_authentication(msg: EmailMessage, r: Report) -> None:
    results = " ".join(msg.get_all("Authentication-Results", []) or []).lower()
    if not results:
        r.add("auth", "low", "No Authentication-Results header (cannot confirm SPF/DKIM/DMARC)", 1)
        return
    for mech, weight in (("spf", 2), ("dkim", 2), ("dmarc", 3)):
        found = re.search(rf"\b{mech}=(\w+)", results)
        status = found.group(1) if found else "missing"
        if status == "pass":
            r.add("auth", "info", f"{mech.upper()} pass", 0)
        elif status in {"fail", "softfail", "permerror"}:
            r.add("auth", "high", f"{mech.upper()} {status}", weight)
        else:
            r.add("auth", "medium", f"{mech.upper()} {status}", 1)


def check_sender(msg: EmailMessage, r: Report) -> None:
    display, from_addr = parseaddr(str(msg.get("From", "")))
    r.from_addr = f"{display} <{from_addr}>" if display else from_addr
    from_domain = domain_of(from_addr)

    reply_to = msg.get("Reply-To")
    if reply_to and base_domain(domain_of(str(reply_to))) != base_domain(from_domain):
        r.add("sender", "high", f"Reply-To ({domain_of(str(reply_to))}) differs from From ({from_domain}) - "
                                "replies go to someone else", 3)

    return_path = msg.get("Return-Path")
    if return_path and base_domain(domain_of(str(return_path))) != base_domain(from_domain):
        r.add("sender", "medium", f"Return-Path domain {domain_of(str(return_path))} differs from From domain", 1)

    lowered = display.lower().replace(" ", "")
    for brand in BRANDS:
        if brand in lowered and brand not in from_domain.replace("-", ""):
            r.add("sender", "high", f"Display name mentions '{brand}' but address is {from_addr}", 3)
            break


def check_routing(msg: EmailMessage, r: Report) -> None:
    received = msg.get_all("Received", []) or []
    r.hops = [" ".join(str(h).split())[:140] for h in received]
    ips = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", " ".join(map(str, received)))
    if ips:
        r.add("routing", "info", f"{len(received)} hop(s); originating IP {ips[-1]}", 0)
    if any("unknown" in str(h).lower() for h in received):
        r.add("routing", "low", "Sending server did not have matching reverse DNS ('unknown')", 1)


def body_parts(msg: EmailMessage) -> tuple[str, str]:
    text, html = "", ""
    for part in msg.walk():
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, KeyError):
            content = part.get_payload(decode=True).decode("utf-8", "replace")
        if ctype == "text/plain":
            text += content
        elif ctype == "text/html":
            html += content
    return text, html


def assess_url(url: str, shown: str) -> list[tuple[str, str, int]]:
    issues = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return issues
    if parsed.scheme == "http":
        issues.append(("medium", "uses plain HTTP", 1))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        issues.append(("high", "raw IP address", 3))
    if "xn--" in host:
        issues.append(("high", "punycode (possible homograph)", 3))
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        issues.append(("medium", f"risky TLD .{host.rsplit('.', 1)[-1]}", 2))
    label = base_domain(host).split(".")[0]
    for token in re.split(r"[-.]", host):
        normal = token.translate(LEET)
        for brand in BRANDS:
            if len(brand) < 4:
                continue
            if (normal == brand and token != brand) or (
                    token != brand and len(token) >= 5 and SequenceMatcher(None, normal, brand).ratio() >= 0.85):
                issues.append(("high", f"look-alike of '{brand}' in {host}", 3))
                break
            if token == brand and label != brand:
                issues.append(("high", f"brand '{brand}' used on unrelated domain {base_domain(host)}", 3))
                break
    shown_domain = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", shown.lower())
    if shown_domain and base_domain(shown_domain.group(0)) != base_domain(host):
        issues.append(("high", f"link text shows {shown_domain.group(0)} but goes to {host}", 4))
    return issues


def check_links(text: str, html: str, r: Report) -> None:
    extractor = LinkExtractor()
    extractor.feed(html)
    links = list(extractor.links)
    seen = {u for u, _ in links}
    for url in re.findall(r"https?://[^\s\"'<>)]+", text):
        if url not in seen:
            links.append((url, ""))
            seen.add(url)
    worst = 0
    for url, shown in links:
        issues = assess_url(url, shown)
        r.urls.append({"url": url, "text": shown, "issues": [d for _, d, _ in issues]})
        points = sum(p for _, _, p in issues)
        if points > worst:
            worst = points
        for sev, detail, _ in issues:
            r.add("links", sev, detail, 0)
    if worst:
        r.add("links", "high" if worst >= 3 else "medium", f"Most suspicious link scores {worst}", min(worst, 6))


def check_attachments(msg: EmailMessage, r: Report) -> None:
    for part in msg.iter_attachments():
        name = part.get_filename() or "(unnamed)"
        data = part.get_payload(decode=True) or b""
        suffixes = [s.lower() for s in Path(name).suffixes]
        info = {"name": name, "type": part.get_content_type(), "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}
        r.attachments.append(info)
        if suffixes and suffixes[-1] in RISKY_EXTENSIONS:
            r.add("attachment", "high", f"{name}: risky file type {suffixes[-1]}", 4)
        if len(suffixes) >= 2 and suffixes[-1] in ARCHIVE_EXTENSIONS | RISKY_EXTENSIONS:
            r.add("attachment", "high", f"{name}: double extension disguises the real type", 3)
        elif suffixes and suffixes[-1] in ARCHIVE_EXTENSIONS:
            r.add("attachment", "medium", f"{name}: archive can hide malware from scanners", 1)


def check_language(subject: str, text: str, r: Report) -> None:
    body = f"{subject}\n{re.sub(r'<[^>]+>', ' ', text)}".lower()
    urgent = sorted({m.group(0) for p in URGENCY for m in re.finditer(p, body)})
    creds = sorted({m.group(0) for p in CREDENTIAL for m in re.finditer(p, body)})
    if urgent:
        r.add("language", "medium", f"Urgency / pressure: {', '.join(urgent[:5])}", min(len(urgent), 3))
    if creds:
        r.add("language", "medium", f"Asks for action on credentials or content: {', '.join(creds[:4])}", 2)


def analyse(path: Path) -> Report:
    msg = load(path)
    r = Report(file=path.name, subject=str(msg.get("Subject", "")))
    text, html = body_parts(msg)
    check_authentication(msg, r)
    check_sender(msg, r)
    check_routing(msg, r)
    check_links(text, html, r)
    check_attachments(msg, r)
    check_language(r.subject, text + html, r)
    return r


# ------------------------------------------------------------------ output ---
ICON = {"info": " ", "low": "-", "medium": "!", "high": "X"}


def print_report(r: Report) -> None:
    print("=" * 72)
    print(f"{r.file}\nSubject: {r.subject}\nFrom:    {r.from_addr}")
    print(f"VERDICT: {r.verdict}  (score {r.score})")
    print("-" * 72)
    for f in r.findings:
        if f.severity != "info" or f.category in {"auth", "routing"}:
            print(f" [{ICON[f.severity]}] {f.category:10} {f.detail}")
    for u in r.urls:
        print(f"     url  {u['url']}")
    for a in r.attachments:
        print(f"     file {a['name']} ({a['size']} bytes) sha256={a['sha256'][:16]}...")


def markdown(r: Report) -> str:
    lines = [f"# Email analysis: {r.file}", "", f"**Verdict: {r.verdict}** (score {r.score})", "",
             f"- Subject: {r.subject}", f"- From: {r.from_addr}", "", "## Findings", "",
             "| Category | Severity | Detail |", "|---|---|---|"]
    lines += [f"| {f.category} | {f.severity} | {f.detail} |" for f in r.findings]
    lines += ["", "## Links", ""] + ([f"- `{u['url']}` - {', '.join(u['issues']) or 'no issues'}" for u in r.urls] or ["None"])
    lines += ["", "## Attachments", ""] + ([f"- `{a['name']}` {a['type']}, {a['size']} bytes, SHA-256 `{a['sha256']}`"
                                           for a in r.attachments] or ["None"])
    lines += ["", "## Received chain (newest first)", ""] + [f"1. `{h}`" for h in r.hops]
    lines += ["", "## Recommended actions", ""]
    if r.verdict == "CLEAN":
        lines.append("- No action needed beyond normal caution.")
    else:
        lines += ["- Do not click links or open attachments.",
                  "- Report the message to the security team / phishing mailbox.",
                  "- Search for the same sender, subject and attachment hash across other mailboxes.",
                  "- If anyone entered credentials: reset the password, revoke sessions, review MFA methods."]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyse .eml files for phishing indicators.")
    parser.add_argument("path", type=Path, help=".eml file or a folder of them")
    parser.add_argument("--report", type=Path, help="Folder to write Markdown reports into")
    args = parser.parse_args()

    files = sorted(args.path.glob("*.eml")) if args.path.is_dir() else [args.path]
    if not files or not files[0].exists():
        print(f"No .eml files found at {args.path}")
        return 2
    worst = 0
    for f in files:
        r = analyse(f)
        print_report(r)
        worst = max(worst, ["CLEAN", "SUSPICIOUS", "MALICIOUS"].index(r.verdict))
        if args.report:
            args.report.mkdir(parents=True, exist_ok=True)
            out = args.report / f"{f.stem}.md"
            out.write_text(markdown(r), encoding="utf-8")
            print(f"     report -> {out}")
    return worst


if __name__ == "__main__":
    sys.exit(main())
