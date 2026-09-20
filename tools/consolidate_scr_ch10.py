#!/usr/bin/env python3
"""Consolidate Security Code Review Ch10: 7 minis → 3 family chapters.

Also builds appendix/secure-implementations-reference/ and removes Chapter 11
(platform configuration) from the book tree.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BOOK = REPO / "docs" / "minibooks" / "security-code-review"
APPENDIX = BOOK / "appendix" / "secure-implementations-reference"

FAMILIES: list[dict] = [
    {
        "slug": "5-01-review-identity-and-federation.md",
        "num": "5.1",
        "title": "Review Identity and Federation",
        "keywords": ["oauth", "oidc", "saml", "federation", "pkce"],
        "description": (
            "Review OAuth 2.0, OpenID Connect, and SAML as one federation family."
        ),
        "shared": (
            "Identity and federation bugs share one question: can an attacker hijack "
            "the redirect or assertion path and become another user? Review redirect URI "
            "binding, CSRF/`state`/`nonce`, client authentication, signature and audience "
            "checks, and token storage—not only whether a library call exists."
        ),
        "members": [
            ("5-01-review-oauth-implementation.md", "OAuth 2.0", "oauth"),
            ("5-02-review-oidc-implementation.md", "OpenID Connect", "oidc"),
            ("10-04-review-saml-federation.md", "SAML federation", "saml"),
        ],
    },
    {
        "slug": "5-02-review-tokens-and-api-trust.md",
        "num": "5.2",
        "title": "Review Tokens and API Trust",
        "keywords": ["jwt", "jwks", "api keys", "request signing", "hmac"],
        "description": (
            "Review JWT issuance/validation and API key / request-signing designs together."
        ),
        "shared": (
            "Tokens and API credentials prove who may call what. Review how they are "
            "**minted**, **validated**, **rotated**, and **bound to transport**—not only "
            "whether `jwt.decode` or a header check exists. For parse-time JWT flaws "
            "(algorithm confusion, skipped signature), also use Chapter 4.5."
        ),
        "members": [
            ("5-03-review-jwt-implementation.md", "JWT implementation", "jwt"),
            (
                "10-07-review-api-keys-and-request-signing.md",
                "API keys and request signing",
                "api-keys",
            ),
        ],
    },
    {
        "slug": "5-03-review-transport-and-service-identity.md",
        "num": "5.3",
        "title": "Review Transport and Service Identity",
        "keywords": ["tls", "mtls", "certificates", "service identity"],
        "description": (
            "Review TLS/SSL protocol settings and mTLS service identity as one transport family."
        ),
        "shared": (
            "Transport and service-identity failures let an attacker sit on the wire or "
            "impersonate a peer. Review protocol versions, cipher and certificate "
            "validation, hostname checks, and—when mutual TLS is claimed—whether both "
            "sides present and verify the expected identity."
        ),
        "members": [
            ("10-05-review-tls-ssl-protocol.md", "TLS and SSL protocol", "tls"),
            ("10-06-review-mtls-service-identity.md", "mTLS and service identity", "mtls"),
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
    m = re.search(rf"^## {re.escape(heading)}\s*\n", body, re.M)
    if not m:
        return None
    start = m.end()
    nxt = re.search(r"^## ", body[start:], re.M)
    end = start + nxt.start() if nxt else len(body)
    return body[start:end].strip() + "\n"


def first_para_after_title(body: str) -> str:
    m = re.search(r"^## 10\.\d+[^\n]*\n\n(.+?)(?:\n\n|\n## )", body, re.S)
    if m:
        return m.group(1).strip()
    return ""


def extract_what(body: str) -> str:
    return (
        section_after(body, "What This Topic Is")
        or section_after(body, "What This Vulnerability Is")
        or ""
    )


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
    return [
        ln.strip()
        for ln in block.splitlines()
        if ln.strip().startswith("- [") and "Appendix" not in ln
    ]


def build_guiding(family: dict, sources: dict[str, str]) -> str:
    members = family["members"]
    primary_name = members[0][0]
    primary = strip_fm(sources[primary_name])[1]

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
        "This chapter consolidates related implementation topics into one family so we "
        "learn a shared model once, then apply variant-specific checks. Dense library "
        "catalogs and multi-language samples stay in the "
        f"[appendix for this family](appendix/secure-implementations-reference/{family['slug']}).",
        "",
        "## Shared Review Model",
        "",
        "Across every variant below, keep the same evidence habit: name the **protocol "
        "step or credential**, the **trust decision**, the **missing control**, the "
        "**impact**, and a **test** that would prove a fix.",
        "",
        "## Variants in This Family",
        "",
    ]

    for fname, label, anchor in members:
        body = strip_fm(sources[fname])[1]
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
            f"**Appendix detail:** [{label} reference]"
            f"(appendix/secure-implementations-reference/{family['slug']}#{anchor}).",
            "",
        ]

    sample = extract_sample(primary)
    walk = extract_walk(primary)
    risk = extract_risk(primary)
    fix = extract_fix(primary)
    verify_blocks = [
        extract_verify(strip_fm(sources[m[0]])[1]) for m in members
    ]

    primary_label = members[0][1]
    lines += [
        f"## Worked Example ({primary_label})",
        "",
        f"We walk **{primary_label}** in depth. Apply the same tracing steps to the other "
        "variants, adjusting protocol steps and sinks from the tables above.",
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
        "Primary safer patterns for the worked example follow. For other languages and "
        "variant-specific fixes, use the "
        f"[family appendix](appendix/secure-implementations-reference/{family['slug']}).",
        "",
        fix.strip() if fix else "",
        "",
        "## Verify During Review",
        "",
        "Family checklist (union of former topic checks):",
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
        "## Implementation Reference (Appendix)",
        "",
        "Library sinks, multi-language examples, and full fix catalogs for every variant "
        f"live in **[{family['num']} reference — {family['title']}]"
        f"(appendix/secure-implementations-reference/{family['slug']})**.",
        "",
        "## Reference",
        "",
        f"- Appendix — [{family['num']} reference]"
        f"(appendix/secure-implementations-reference/{family['slug']})",
        "",
    ]
    ref_seen: set[str] = set()
    for fname, _, _ in members:
        for r in extract_refs(strip_fm(sources[fname])[1]):
            if r not in ref_seen:
                ref_seen.add(r)
                lines.append(r)
    lines.append("")
    return "\n".join(lines)


def build_appendix(family: dict, sources: dict[str, str]) -> str:
    lines = [
        "---",
        f'title: "{family["num"]} Reference — {family["title"]}"',
        "description: >",
        f"  Libraries, multi-language examples, and fixes for {family['title']}.",
        "---",
        "",
        f"# {family['num']} Reference — {family['title']}",
        "",
        "This appendix supports the guiding chapter "
        f"**[{family['num']} - {family['title']}](../../{family['slug']})**. "
        "Each section below preserves the dense material from a former topic chapter.",
        "",
        f"**Back to chapter:** [{family['num']} - {family['title']}](../../{family['slug']})",
        "",
    ]
    for fname, label, anchor in family["members"]:
        raw = strip_fm(sources[fname])[1]
        raw = re.sub(r"^## 10\.\d+[^\n]*\n+", "", raw)
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
        'title: "Appendix — Secure Implementations Reference"',
        "description: >",
        "  Library sinks, multi-language examples, and fixes for Chapter 5",
        "  implementation families.",
        "---",
        "",
        "# Appendix — Secure Implementations Reference",
        "",
        "Code-density material for Part IV, grouped to match the **three** guiding "
        "family chapters. Use a guiding chapter for method; open the matching "
        "appendix row for libraries, sinks, and multi-language fixes.",
        "",
        "Hub: [Chapter 5 overview](../../5-review-secure-implementations.md).",
        "",
        "| Family | Guiding chapter | Reference |",
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


def remove_chapter_11() -> None:
    for p in sorted(BOOK.glob("11-*.md")):
        p.unlink()
        print(f"removed {p.name}")


def main() -> int:
    sources: dict[str, str] = {}
    for fam in FAMILIES:
        for m, _, _ in fam["members"]:
            path = BOOK / m
            if not path.exists():
                print(f"missing {m}", file=sys.stderr)
                return 1
            sources[m] = read(path)

    APPENDIX.mkdir(parents=True, exist_ok=True)

    for fam in FAMILIES:
        guiding = build_guiding(fam, sources)
        (BOOK / fam["slug"]).write_text(guiding, encoding="utf-8")
        app = build_appendix(fam, sources)
        (APPENDIX / fam["slug"]).write_text(app, encoding="utf-8")
        print(f"wrote {fam['slug']} + appendix")

    # Remove former mini-chapters (including ones overwritten only if slug collided)
    new_slugs = {f["slug"] for f in FAMILIES}
    for fam in FAMILIES:
        for old, _, _ in fam["members"]:
            if old in new_slugs:
                continue
            path = BOOK / old
            if path.exists():
                path.unlink()
                print(f"removed old {old}")

    # Leftover 10-0N that are not family slugs
    for p in sorted(BOOK.glob("10-0*-review-*.md")):
        if p.name not in new_slugs:
            p.unlink()
            print(f"removed leftover {p.name}")

    write_appendix_index(FAMILIES)
    print("wrote appendix index")

    remove_chapter_11()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
