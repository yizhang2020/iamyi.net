#!/usr/bin/env python3
"""Consolidate Security Code Review Ch4: 42 mini-chapters → 10 family chapters.

Also consolidates appendix/code-level-reference to match, and replaces old
guiding pages; former mini-chapter files are removed (no stubs).
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BOOK = REPO / "docs" / "minibooks" / "security-code-review"
APPENDIX = BOOK / "appendix" / "code-level-reference"
OLD_DIR = BOOK / "_archived_ch4_minis"  # unused; we overwrite with stubs

# new_slug, new_num, title, members [(old_file, old_label, subsection_slug)]
# Primary walkthrough = first member.
FAMILIES: list[dict] = [
    {
        "slug": "4-01-review-xss.md",
        "num": "4.1",
        "title": "Review XSS",
        "keywords": ["xss", "cross-site scripting", "output encoding", "DOM XSS"],
        "description": "Review stored, reflected, and DOM XSS as one HTML/script-context family.",
        "shared": (
            "Cross-site scripting is the same core failure in three delivery shapes: "
            "untrusted data reaches an HTML or JavaScript sink without context-appropriate "
            "encoding. The control is almost always **encode (or sanitize) at the sink for "
            "the output context**—not denylist filters on input alone."
        ),
        "members": [
            ("4-01-review-stored-xss.md", "Stored XSS", "stored"),
            ("4-02-review-reflected-xss.md", "Reflected XSS", "reflected"),
            ("4-03-review-dom-xss.md", "DOM XSS", "dom"),
        ],
    },
    {
        "slug": "4-02-review-interpreter-injection.md",
        "num": "4.2",
        "title": "Review Interpreter Injection",
        "keywords": ["sql injection", "command injection", "SSTI", "code injection"],
        "description": "Review SQL, command, code, JSON, and template injection as interpreter-boundary failures.",
        "shared": (
            "Interpreter injection happens when attacker-controlled data is concatenated into "
            "a language the runtime will parse—SQL, shell, eval, templates, or crafted JSON "
            "structures. The shared review move is to separate **structure from data** "
            "(parameters, argv arrays, safe template APIs) and refuse user influence over "
            "identifiers that must stay allowlisted."
        ),
        "members": [
            ("4-04-review-sql-injection.md", "SQL injection", "sql"),
            ("4-05-review-command-injection.md", "Command injection", "command"),
            ("4-06-review-code-injection.md", "Code injection", "code"),
            ("4-07-review-json-injection.md", "JSON injection", "json"),
            ("4-10-review-ssti.md", "Server-side template injection", "ssti"),
        ],
    },
    {
        "slug": "4-03-review-parsers-and-unsafe-reconstitution.md",
        "num": "4.3",
        "title": "Review Parsers and Unsafe Reconstitution",
        "keywords": ["XXE", "deserialization", "JSP include", "parser security"],
        "description": "Review XXE, dynamic inclusion, and insecure deserialization as parser-trust failures.",
        "shared": (
            "Parsers and object reconstitutors turn bytes into privileged behavior. When the "
            "parser follows external entities, includes paths, or deserializes attacker graphs, "
            "we inherit that power. Review whether the parser is locked down and whether "
            "untrusted streams ever reach it."
        ),
        "members": [
            ("4-09-review-xxe.md", "XXE", "xxe"),
            ("4-08-review-dynamic-jsp-inclusion.md", "Dynamic JSP inclusion", "jsp-include"),
            ("4-38-review-insecure-deserialization.md", "Insecure deserialization", "deserialization"),
        ],
    },
    {
        "slug": "4-04-review-paths-uploads-and-files.md",
        "num": "4.4",
        "title": "Review Paths, Uploads, and Files",
        "keywords": ["path traversal", "file upload", "temporary files", "file parsing"],
        "description": "Review path traversal, uploads, temp files, and unsafe file parsing together.",
        "shared": (
            "File and path bugs share one question: can a name or payload escape the intended "
            "directory or content type? Resolve and constrain paths, validate uploads by "
            "content and policy, and treat parsers of user files as hostile input."
        ),
        "members": [
            ("4-11-review-path-traversal.md", "Path traversal", "path-traversal"),
            ("4-29-review-insecure-file-path-handling.md", "Insecure file path handling", "file-path"),
            ("4-30-review-insecure-file-upload.md", "Insecure file upload", "upload"),
            ("4-27-review-insecure-temporary-files.md", "Insecure temporary files", "temp-files"),
            ("4-28-review-insecure-file-parsing.md", "Insecure file parsing", "file-parsing"),
        ],
    },
    {
        "slug": "4-05-review-authentication-session-and-access.md",
        "num": "4.5",
        "title": "Review Authentication, Session, and Access Control",
        "keywords": ["CSRF", "session", "IDOR", "authorization", "JWT", "cookies"],
        "description": "Review CSRF, sessions, passwords, authz/IDOR, JWT-at-code-level, and cookie flags.",
        "shared": (
            "These findings ask who is acting, what binds the request to that actor, and what "
            "they are allowed to touch. Review session lifecycle, CSRF defenses, password "
            "handling, object-level authorization, and cookie flags together. For OAuth/OIDC/"
            "SAML protocol depth, continue in Chapter 10."
        ),
        "members": [
            ("4-18-review-authentication-and-authorization.md", "Authentication and authorization", "authz"),
            ("4-21-review-idor.md", "IDOR", "idor"),
            ("4-20-review-forced-browsing.md", "Forced browsing", "forced-browsing"),
            ("4-16-review-broken-session-management.md", "Broken session management", "session"),
            ("4-14-review-csrf.md", "CSRF", "csrf"),
            ("4-19-review-broken-password-lifecycle.md", "Broken password lifecycle", "password"),
            ("4-17-review-jwt-security.md", "JWT security (code-level)", "jwt"),
            ("4-34-review-insecure-cookie-configuration.md", "Insecure cookie configuration", "cookies"),
        ],
    },
    {
        "slug": "4-06-review-ssrf-and-egress.md",
        "num": "4.6",
        "title": "Review SSRF and Egress",
        "keywords": ["SSRF", "egress", "exfiltration", "URL fetch"],
        "description": "Review server-side request forgery and internal/egress exfiltration as outbound trust.",
        "shared": (
            "When user input influences where the server connects or what it sends outward, "
            "the server becomes a proxy into internal networks or partner systems. Review "
            "URL allowlists, scheme/host constraints, and whether responses or outbound "
            "channels can leak secrets."
        ),
        "members": [
            ("4-15-review-ssrf.md", "SSRF", "ssrf"),
            ("4-25-review-internal-and-egress-exfiltration.md", "Internal and egress exfiltration", "egress"),
        ],
    },
    {
        "slug": "4-07-review-information-disclosure-and-logging.md",
        "num": "4.7",
        "title": "Review Information Disclosure and Logging",
        "keywords": ["error disclosure", "logging", "username enumeration", "sensitive data"],
        "description": "Review errors, URLs, enumeration, comments, and sensitive logging as disclosure paths.",
        "shared": (
            "Disclosure findings leak secrets or decision logic through messages, URLs, "
            "comments, or logs. Ask what a stranger learns from each channel and whether "
            "sensitive fields are redacted before they leave the trust boundary."
        ),
        "members": [
            ("4-22-review-error-page-disclosure.md", "Error page disclosure", "errors"),
            ("4-23-review-sensitive-data-in-url.md", "Sensitive data in URL", "url-data"),
            ("4-24-review-username-enumeration.md", "Username enumeration", "enumeration"),
            ("4-26-review-sensitive-logging.md", "Sensitive logging", "sensitive-logging"),
            ("4-40-review-secure-logging.md", "Secure logging", "secure-logging"),
            ("4-32-review-sensitive-code-comments.md", "Sensitive code comments", "comments"),
        ],
    },
    {
        "slug": "4-08-review-cryptography-in-application-code.md",
        "num": "4.8",
        "title": "Review Cryptography in Application Code",
        "keywords": ["cryptography", "encryption", "hashing", "non-standard crypto"],
        "description": "Review cryptographic implementation, non-standard crypto, and enc/dec mistakes.",
        "shared": (
            "Application crypto fails when we invent protocols, misuse modes/IVs, or treat "
            "encoding as confidentiality. Prefer vetted libraries, current algorithms, and "
            "explicit key management—then verify those choices in code."
        ),
        "members": [
            ("4-13-review-cryptographic-implementation.md", "Cryptographic implementation", "implementation"),
            ("4-37-review-non-standard-crypto-practices.md", "Non-standard crypto practices", "non-standard"),
            ("4-39-review-encryption-decryption-mistakes.md", "Encryption and decryption mistakes", "enc-dec"),
        ],
    },
    {
        "slug": "4-09-review-secrets-defaults-and-dangerous-apis.md",
        "num": "4.9",
        "title": "Review Secrets, Defaults, and Dangerous APIs",
        "keywords": ["hardcoded secrets", "dangerous functions", "secure defaults", "client-side validation"],
        "description": "Review secrets, obsolete code, dangerous APIs, framework defaults, and client-only validation.",
        "shared": (
            "These patterns are foot-guns and misplaced trust: secrets in source, obsolete "
            "APIs, dangerous primitives, weak framework defaults, and validation that exists "
            "only in the browser. Hunt for them as inventory passes, then prove impact."
        ),
        "members": [
            ("4-33-review-hardcoded-secrets.md", "Hardcoded secrets", "secrets"),
            ("4-36-review-dangerous-functions.md", "Dangerous functions", "dangerous-functions"),
            ("4-35-review-obsolete-code.md", "Obsolete code", "obsolete"),
            ("4-31-review-framework-secure-defaults.md", "Framework secure defaults", "defaults"),
            ("4-12-review-client-side-validation.md", "Client-side validation", "client-validation"),
            ("4-42-review-insecure-coding-practice.md", "Insecure coding practice", "insecure-practice"),
        ],
    },
    {
        "slug": "4-10-review-software-supply-chain.md",
        "num": "4.10",
        "title": "Review Software Supply Chain",
        "keywords": ["supply chain", "dependencies", "SBOM", "package integrity"],
        "description": "Review dependency and build-input trust for application security code review.",
        "shared": (
            "Supply-chain review asks whether build and runtime trust unvetted packages, "
            "scripts, or artifacts. Evidence lives in lockfiles, registries, CI, and "
            "import graphs—not only in application sinks."
        ),
        "members": [
            ("4-41-review-software-supply-chain.md", "Software supply chain", "supply-chain"),
        ],
    },
]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_fm(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---\n", 3)
    if end < 0:
        return {}, text
    return {}, text[end + 5 :]


def section_after(body: str, heading: str) -> str | None:
    """Return content under ## heading until next ##."""
    m = re.search(rf"^## {re.escape(heading)}\s*\n", body, re.M)
    if not m:
        return None
    start = m.end()
    nxt = re.search(r"^## ", body[start:], re.M)
    end = start + nxt.start() if nxt else len(body)
    return body[start:end].strip() + "\n"


def first_para_after_title(body: str) -> str:
    """Opening paragraph under the chapter ## 4.x title."""
    m = re.search(r"^## 4\.\d+[^\n]*\n\n(.+?)(?:\n\n|\n## )", body, re.S)
    if m:
        return m.group(1).strip()
    return ""


def extract_what(body: str) -> str:
    return section_after(body, "What This Vulnerability Is") or ""


def extract_chars(body: str) -> str:
    return section_after(body, "Vulnerability Characteristics (Where to Identify Them)") or ""


def extract_sample(body: str) -> str:
    return section_after(body, "Sample Vulnerable Code in Python") or ""


def extract_walk(body: str) -> str:
    return section_after(body, "Step-by-Step Review Walkthrough") or ""


def extract_risk(body: str) -> str:
    return section_after(body, "Risk Impact Analysis") or ""


def extract_fix(body: str) -> str:
    return section_after(body, "Fix: Safer Patterns and Libraries to Use") or ""


def extract_verify(body: str) -> str:
    return section_after(body, "Verify During Review") or ""


def extract_refs(body: str) -> list[str]:
    block = section_after(body, "Reference") or ""
    return [ln.strip() for ln in block.splitlines() if ln.strip().startswith("- [") and "Appendix" not in ln]


def build_guiding(family: dict) -> str:
    members = family["members"]
    primary_name = members[0][0]
    primary = strip_fm(read(BOOK / primary_name))[1]

    lines: list[str] = [
        "---",
        f"title: {family['title']}",
        "keywords:",
    ]
    for kw in family["keywords"]:
        lines.append(f"  - {kw}")
    lines += [
        f"description: {family['description']}",
        "---",
        "",
        f"## {family['num']} - {family['title']}",
        "",
        family["shared"],
        "",
        "This chapter consolidates related mini-topics into one family so we learn a "
        "shared model once, then apply variant-specific checks. Dense payloads, sinks, "
        "and multi-language catalogs stay in the "
        f"[appendix for this family](appendix/code-level-reference/{family['slug']}).",
        "",
        "## Shared Review Model",
        "",
        "Across every variant below, keep the same evidence habit: name the **source**, "
        "the **sink**, the **missing control**, the **impact**, and a **test** that would "
        "prove a fix.",
        "",
        "## Variants in This Family",
        "",
    ]

    for fname, label, anchor in members:
        body = strip_fm(read(BOOK / fname))[1]
        opener = first_para_after_title(body) or extract_what(body).split("\n\n")[0]
        chars = extract_chars(body)
        lines += [
            f"### {label} {{: #{anchor} }}",
            "",
            opener,
            "",
        ]
        if chars.strip():
            lines += ["**Where to look**", "", chars.strip(), ""]
        lines += [
            f"**Appendix detail:** [{label} code reference]"
            f"(appendix/code-level-reference/{family['slug']}#{anchor}).",
            "",
        ]

    # Primary worked example
    sample = extract_sample(primary)
    walk = extract_walk(primary)
    risk = extract_risk(primary)
    fix = extract_fix(primary)
    verify_blocks = [extract_verify(strip_fm(read(BOOK / m[0]))[1]) for m in members]

    primary_label = members[0][1]
    lines += [
        f"## Worked Example ({primary_label})",
        "",
        f"We walk **{primary_label}** in depth. Apply the same tracing steps to the other "
        "variants, adjusting sources and sinks from the tables above.",
        "",
        "### Sample vulnerable code (Python)",
        "",
        sample.strip() if sample else "_See appendix._",
        "",
        "### Step-by-step review walkthrough",
        "",
        walk.strip() if walk else "",
        "",
        "## Risk Impact (Family)",
        "",
        risk.strip() if risk else "",
        "",
        "## Fix Principles",
        "",
        f"Primary safer patterns for the worked example follow. For other languages and "
        f"variant-specific fixes, use the "
        f"[family appendix](appendix/code-level-reference/{family['slug']}).",
        "",
        fix.strip() if fix else "",
        "",
        "## Verify During Review",
        "",
        "Family checklist (union of former mini-chapter checks):",
        "",
    ]
    seen: set[str] = set()
    for vb in verify_blocks:
        for ln in (vb or "").splitlines():
            s = ln.strip()
            if s.startswith("- ") and s not in seen:
                seen.add(s)
                lines.append(s)
    lines += [
        "",
        "## Code Reference (Appendix)",
        "",
        "Payloads, language-specific sinks, multi-language examples, and full fix catalogs "
        f"for every variant live in **[{family['num']} code reference — {family['title']}]"
        f"(appendix/code-level-reference/{family['slug']})**.",
        "",
        "## Reference",
        "",
        f"- Appendix — [{family['num']} code reference](appendix/code-level-reference/{family['slug']})",
        "",
    ]
    ref_seen: set[str] = set()
    for fname, _, _ in members:
        for r in extract_refs(strip_fm(read(BOOK / fname))[1]):
            if r not in ref_seen:
                ref_seen.add(r)
                lines.append(r)
    lines.append("")
    return "\n".join(lines)


def build_appendix(family: dict) -> str:
    lines = [
        "---",
        f'title: "{family["num"]} Code Reference — {family["title"]}"',
        "description: >",
        f"  Payloads, sinks, multi-language examples, and fixes for {family['title']}.",
        "---",
        "",
        f"# {family['num']} Code Reference — {family['title']}",
        "",
        "This appendix supports the guiding chapter "
        f"**[{family['num']} - {family['title']}](../../{family['slug']})**. "
        "Each section below preserves the dense material from a former mini-chapter.",
        "",
        f"**Back to chapter:** [{family['num']} - {family['title']}](../../{family['slug']})",
        "",
    ]
    for fname, label, anchor in family["members"]:
        app_path = APPENDIX / fname
        if not app_path.exists():
            raise FileNotFoundError(app_path)
        raw = strip_fm(read(app_path))[1]
        # Drop leading # title and back-link block; keep ## sections
        raw = re.sub(r"^# .+\n+", "", raw)
        raw = re.sub(
            r"^This appendix supports[\s\S]*?\*\*Back to chapter:\*\*[^\n]+\n+",
            "",
            raw,
        )
        lines += [
            f"## {label} {{: #{anchor} }}",
            "",
            f"From former `{fname}`. "
            f"**Guiding chapter section:** "
            f"[{family['num']} - {family['title']} § {label}]"
            f"(../../{family['slug']}#{anchor}).",
            "",
            raw.strip(),
            "",
        ]
    return "\n".join(lines) + "\n"


def write_appendix_index(families: list[dict]) -> None:
    lines = [
        "---",
        'title: "Appendix — Code-Level Reference"',
        "description: >",
        "  Payloads, language sinks, multi-language examples, and fixes for",
        "  Chapter 4 vulnerability families.",
        "---",
        "",
        "# Appendix — Code-Level Reference",
        "",
        "Code-density material for Part III, grouped to match the **ten** guiding "
        "family chapters. Use a guiding chapter for method; open the matching "
        "appendix row for payloads, sinks, and multi-language fixes.",
        "",
        "Hub: [Chapter 4 overview](../../4-review-code-level-vulnerabilities.md).",
        "",
        "| Family | Guiding chapter | Code reference |",
        "| --- | --- | --- |",
    ]
    for f in families:
        lines.append(
            f"| {f['num']} {f['title']} | "
            f"[{f['num']} - {f['title']}](../../{f['slug']}) | "
            f"[Appendix]({f['slug']}) |"
        )
    lines.append("")
    (APPENDIX / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    # Snapshot old appendix pages before overwrite
    old_apps = {m[0]: read(APPENDIX / m[0]) for fam in FAMILIES for m in fam["members"]}
    # Ensure we read guiding chapters before overwrite
    for fam in FAMILIES:
        for m, _, _ in fam["members"]:
            if not (BOOK / m).exists():
                print(f"missing {m}", file=sys.stderr)
                return 1

    # Build new guiding + appendix
    for fam in FAMILIES:
        guiding = build_guiding(fam)
        (BOOK / fam["slug"]).write_text(guiding, encoding="utf-8")
        # Temporarily restore old appendix content from memory for merge
        for m, _, _ in fam["members"]:
            (APPENDIX / m).write_text(old_apps[m], encoding="utf-8")
        app = build_appendix(fam)
        (APPENDIX / fam["slug"]).write_text(app, encoding="utf-8")
        print(f"wrote {fam['slug']} + appendix")

    # Remove old per-mini appendix files; keep family appendix + index
    keep = {f["slug"] for f in FAMILIES} | {"index.md"}
    for p in APPENDIX.glob("4-*-review-*.md"):
        if p.name not in keep:
            p.unlink()
            print(f"removed old appendix {p.name}")

    # Remove former mini-chapter files (no stubs — numbers collide with family slugs)
    new_slugs = {f["slug"] for f in FAMILIES}
    for fam in FAMILIES:
        for old, _label, _anchor in fam["members"]:
            if old in new_slugs:
                continue
            path = BOOK / old
            if path.exists():
                path.unlink()
                print(f"removed old {old}")

    write_appendix_index(FAMILIES)
    print("wrote appendix index")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
