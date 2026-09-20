#!/usr/bin/env python3
"""Evaluate writing quality for supported security topic books.

Supported scopes:
  - docs/minibooks/security-code-review/**/*.md
  - docs/minibooks/hackers-mindset/**/*.md  (excludes materials/ and _template*)

Scores sections, chapters, and the overall book against rubric.yaml.
Appends history and regenerates the dashboard after every run.

Usage:
  python3 tools/writing-eval/evaluate.py
  python3 tools/writing-eval/evaluate.py --scope hackers-mindset
  python3 tools/writing-eval/evaluate.py path/to/ch.md
  python3 tools/writing-eval/evaluate.py --hook-stdin
  python3 tools/writing-eval/evaluate.py --history --scope security-code-review
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # fallback parser for our simple rubric if PyYAML missing

ROOT = Path(__file__).resolve().parents[2]
EVAL_ROOT = Path(__file__).resolve().parent
RUBRIC_PATH = EVAL_ROOT / "rubric.yaml"
HISTORY_ROOT = EVAL_ROOT / "history"

BOOKS: dict[str, dict[str, Any]] = {
    "security-code-review": {
        "id": "security-code-review",
        "label": "Security Code Review",
        "rel": Path("docs") / "topics" / "security-code-review",
        "exclude_names": {"index.md"},
        "exclude_dir_names": {"_eval", "eval-history", "materials"},
        "exclude_name_prefixes": ("_template",),
    },
    "hackers-mindset": {
        "id": "hackers-mindset",
        "label": "Hacker's Mindset",
        "rel": Path("docs") / "topics" / "hackers-mindset",
        "exclude_names": {"index.md"},
        "exclude_dir_names": {"_eval", "eval-history", "materials"},
        "exclude_name_prefixes": ("_template",),
    },
}

DEFAULT_BOOK = "security-code-review"

# Backward-compatible aliases used by older helpers; prefer book_paths().
BOOK_REL = BOOKS[DEFAULT_BOOK]["rel"]
DEFAULT_SCOPE = ROOT / BOOK_REL
HISTORY_DIR = HISTORY_ROOT / DEFAULT_BOOK
HISTORY_JSONL = HISTORY_DIR / "scores.jsonl"
LATEST_JSON = HISTORY_DIR / "latest.json"
DASHBOARD_MD = HISTORY_DIR / "dashboard.md"

FEAR_WORDS = re.compile(
    r"\b(catastrophic|destroys?|completely breaks|nightmare|apocalyptic|"
    r"utterly|devastating|crippling)\b",
    re.I,
)
VAGUE_WORDS = re.compile(
    r"\b(basically|somehow|obviously|clearly|stuff|things|very|"
    r"just simply|a bit|kind of|sort of)\b",
    re.I,
)
BARE_CLAIM = re.compile(
    r"\b(this is (completely )?(secure|unsafe|vulnerable)|"
    r"this prevents attacks|this is invulnerable)\b",
    re.I,
)
ACTION_START = re.compile(
    r"^(Part\s+[IVXLC0-9]+|Chapter\s+\d+|[\d.]+\s*-?\s*)?"
    r"(Define|Think|Review|Trace|Check|Use|Run|Control|Train|Build|"
    r"Apply|Identify|Map|Validate|Verify|Secure|Prefer|Avoid|Start|"
    r"Generate|Draft|Measure|Explain|Compare|Catalog|Evaluate)\b",
    re.I,
)
NOUN_OK = re.compile(
    r"^(What |Why |How |Preface|Conclusion|References|Appendix|"
    r"Version |Security Code Review|Part |Chapter |"
    r"Vulnerability Characteristics|Attack Payloads|Pattern |"
    r"Language-Specific|Official |Fix |Secure |Risk |"
    r"Core ideas|Methodology|Architecture|Catalog |Case Study)",
    re.I,
)
REVIEWER_TERMS = re.compile(
    r"\b(reviewer|trust boundary|attacker-controlled|source\s*(to|->|/)\s*sink|"
    r"authorization|validation|check(list)?|verify|trace)\b",
    re.I,
)
ACTIONABLE = re.compile(
    r"\b(check|verify|trace|confirm|look for|ensure|require|prefer|avoid|"
    r"do not|must|should)\b",
    re.I,
)
DURABLE = re.compile(
    r"\b(trust boundary|source|sink|attacker-controlled|authorization|"
    r"authentication|validation|output encoding|least privilege|"
    r"defense in depth|threat model|data flow)\b",
    re.I,
)
CWE_OR_OWASP = re.compile(
    r"\b(CWE-\d+|OWASP|NIST|CAPEC|ATT&CK|CERT)\b",
    re.I,
)
REF_MARKER = re.compile(r"\[(\d+)\]\(#ref-\d+\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+|[^)]+\.md)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.M)
FENCE = re.compile(r"^```", re.M)


@dataclass
class CheckResult:
    id: str
    category: str
    score: float
    detail: str
    level: str


@dataclass
class SectionScore:
    heading: str
    level: int
    start_line: int
    word_count: int
    categories: dict[str, float]
    overall: float
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class ChapterScore:
    path: str
    title: str
    tier: str
    word_count: int
    categories: dict[str, float]
    overall: float
    grade: str
    sections: list[SectionScore] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_rubric() -> dict[str, Any]:
    text = RUBRIC_PATH.read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text)
    # Minimal fallback: only need categories weights + grades
    return {
        "categories": {
            "readability": {"weight": 0.20, "name": "Readability"},
            "structure": {"weight": 0.20, "name": "Structure"},
            "precision": {"weight": 0.15, "name": "Precision"},
            "evidence": {"weight": 0.15, "name": "Evidence"},
            "practicality": {"weight": 0.15, "name": "Practicality"},
            "pedagogy": {"weight": 0.15, "name": "Pedagogy"},
        },
        "grades": {
            "excellent": {"min": 90, "label": "Excellent"},
            "strong": {"min": 80, "label": "Strong"},
            "good": {"min": 70, "label": "Good"},
            "needs_work": {"min": 60, "label": "Needs work"},
            "weak": {"min": 0, "label": "Weak"},
        },
        "aggregation": {
            "chapter_section_weight": 0.70,
            "chapter_file_weight": 0.30,
            "book_chapter_weight": 0.80,
            "book_corpus_weight": 0.20,
        },
    }


def grade_for(score: float, rubric: dict[str, Any]) -> str:
    grades = sorted(
        rubric["grades"].items(),
        key=lambda kv: kv[1]["min"],
        reverse=True,
    )
    for _, meta in grades:
        if score >= meta["min"]:
            return meta["label"]
    return "Weak"


def strip_front_matter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    fm_raw = text[3:end].strip()
    body = text[end + 4 :].lstrip("\n")
    meta: dict[str, str] = {}
    for line in fm_raw.splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip().strip("'\"")
    return meta, body


def split_sentences(text: str) -> list[str]:
    # Rough sentence split; good enough for length ceilings
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'])", text.strip())
    return [p.strip() for p in parts if p.strip()]


def word_count(text: str) -> int:
    return len(re.findall(r"\b[\w'-]+\b", text))


def words_in_sentence(s: str) -> int:
    return word_count(s)


def strip_code_fences(text: str) -> str:
    out = []
    in_fence = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)


def extract_lists(text: str) -> list[list[str]]:
    lists: list[list[str]] = []
    current: list[str] = []
    for line in text.splitlines():
        if re.match(r"^(\s*[-*]|\s*\d+\.)\s+", line):
            current.append(line.strip())
        else:
            if current:
                lists.append(current)
                current = []
    if current:
        lists.append(current)
    return lists


def parse_sections(body: str) -> list[dict[str, Any]]:
    lines = body.splitlines()
    headings: list[tuple[int, int, str]] = []
    in_fence = False
    for i, line in enumerate(lines):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if m:
            headings.append((i, len(m.group(1)), m.group(2).strip()))

    if not headings:
        return [
            {
                "heading": "(body)",
                "level": 2,
                "start_line": 1,
                "text": body,
            }
        ]

    sections = []
    for idx, (line_no, level, title) in enumerate(headings):
        end = headings[idx + 1][0] if idx + 1 < len(headings) else len(lines)
        # section text is content after heading until next heading
        chunk = "\n".join(lines[line_no + 1 : end]).strip()
        sections.append(
            {
                "heading": title,
                "level": level,
                "start_line": line_no + 1,
                "text": chunk,
            }
        )
    return sections


def book_paths(book_id: str) -> dict[str, Path]:
    meta = BOOKS[book_id]
    hist = HISTORY_ROOT / book_id
    return {
        "scope": ROOT / meta["rel"],
        "history_dir": hist,
        "history_jsonl": hist / "scores.jsonl",
        "latest_json": hist / "latest.json",
        "dashboard_md": hist / "dashboard.md",
    }


def resolve_book(path: Path) -> str | None:
    """Return book id if path is a scorable markdown file in a known book."""
    try:
        resolved = path.resolve()
    except OSError:
        return None
    if resolved.suffix != ".md":
        return None
    for book_id, meta in BOOKS.items():
        scope = (ROOT / meta["rel"]).resolve()
        try:
            rel = resolved.relative_to(scope)
        except ValueError:
            continue
        if any(part in meta["exclude_dir_names"] for part in rel.parts):
            return None
        if resolved.name in meta["exclude_names"]:
            return None
        if any(resolved.name.startswith(p) for p in meta["exclude_name_prefixes"]):
            return None
        return book_id
    return None


def in_book_scope(path: Path, book_id: str | None = None) -> bool:
    found = resolve_book(path)
    if found is None:
        return False
    if book_id is None:
        return True
    return found == book_id


def infer_tier(path: Path, body: str, book_id: str = DEFAULT_BOOK) -> str:
    name = path.name.lower()
    if book_id == "hackers-mindset":
        # Pattern docs are Tier B: numbered references expected.
        return "B"
    if "research" in name:
        return "B"
    if REF_MARKER.search(body) or re.search(r"^##\s+References\s*$", body, re.M):
        return "B"
    if re.match(r"^\d+-0\d-review-", name) or re.match(r"^4-\d+-review-", name):
        return "A"
    if re.match(r"^(0-|1-|2-|3-|5-|6-|7-|8-|9-|10-|11-|conclusion)", name):
        return "A"
    return "A"


def pct_score(good: int, total: int) -> float:
    if total <= 0:
        return 100.0
    return round(100.0 * good / total, 1)


def mean(vals: list[float]) -> float:
    if not vals:
        return 0.0
    return round(sum(vals) / len(vals), 1)


def weighted_category_scores(
    checks: list[CheckResult],
    rubric: dict[str, Any],
) -> dict[str, float]:
    by_cat: dict[str, list[tuple[float, float]]] = defaultdict(list)
    # default weight 1.0; look up from rubric checks if present
    weight_map = {}
    for c in rubric.get("checks", []) or []:
        weight_map[c["id"]] = float(c.get("weight", 1.0))

    for ch in checks:
        w = weight_map.get(ch.id, 1.0)
        by_cat[ch.category].append((ch.score, w))

    out: dict[str, float] = {}
    for cat in rubric["categories"]:
        pairs = by_cat.get(cat, [])
        if not pairs:
            out[cat] = 0.0
            continue
        num = sum(s * w for s, w in pairs)
        den = sum(w for _, w in pairs)
        out[cat] = round(num / den, 1) if den else 0.0
    return out


def overall_from_categories(cats: dict[str, float], rubric: dict[str, Any]) -> float:
    num = 0.0
    den = 0.0
    for key, meta in rubric["categories"].items():
        w = float(meta["weight"])
        if key in cats:
            num += cats[key] * w
            den += w
    return round(num / den, 1) if den else 0.0


def score_prose_block(
    text: str,
    *,
    level: str,
    category_filter: set[str] | None = None,
) -> list[CheckResult]:
    """Automated checks that apply to section or chapter prose."""
    prose = strip_code_fences(text)
    sentences = split_sentences(prose)
    # paragraphs: blank-line separated
    paras = [p.strip() for p in re.split(r"\n\s*\n", prose) if p.strip()]
    results: list[CheckResult] = []

    def add(cid: str, cat: str, score: float, detail: str) -> None:
        if category_filter and cat not in category_filter:
            return
        results.append(
            CheckResult(id=cid, category=cat, score=score, detail=detail, level=level)
        )

    # sentence soft
    if sentences:
        soft_ok = sum(1 for s in sentences if words_in_sentence(s) <= 50)
        add(
            "sentence_soft_limit",
            "readability",
            pct_score(soft_ok, len(sentences)),
            f"{soft_ok}/{len(sentences)} sentences ≤ 50 words",
        )
        hard_bad = [s for s in sentences if words_in_sentence(s) > 80]
        add(
            "sentence_hard_limit",
            "readability",
            100.0 if not hard_bad else 0.0,
            (
                "no sentence > 80 words"
                if not hard_bad
                else f"{len(hard_bad)} sentence(s) > 80 words"
            ),
        )
    else:
        add("sentence_soft_limit", "readability", 100.0, "no prose sentences")
        add("sentence_hard_limit", "readability", 100.0, "no prose sentences")

    # paragraphs
    if paras:
        soft_ok = 0
        hard_bad = 0
        for p in paras:
            sc = len(split_sentences(p))
            if sc <= 7:
                soft_ok += 1
            if sc > 9:
                hard_bad += 1
        add(
            "paragraph_soft_limit",
            "readability",
            pct_score(soft_ok, len(paras)),
            f"{soft_ok}/{len(paras)} paragraphs ≤ 7 sentences",
        )
        add(
            "paragraph_hard_limit",
            "readability",
            100.0 if hard_bad == 0 else 0.0,
            (
                "no paragraph > 9 sentences"
                if hard_bad == 0
                else f"{hard_bad} paragraph(s) > 9 sentences"
            ),
        )
    else:
        add("paragraph_soft_limit", "readability", 100.0, "no paragraphs")
        add("paragraph_hard_limit", "readability", 100.0, "no paragraphs")

    fear_hits = len(FEAR_WORDS.findall(prose))
    fear_score = max(0.0, 100.0 - fear_hits * 25)
    add("calm_tone", "readability", fear_score, f"{fear_hits} fear/hype hit(s)")

    vague_hits = len(VAGUE_WORDS.findall(prose))
    wc = max(word_count(prose), 1)
    vague_rate = vague_hits / wc
    # 0 hits → 100; ~1 per 100 words → ~50
    vague_score = max(0.0, min(100.0, 100.0 - vague_rate * 5000))
    add(
        "vague_language",
        "precision",
        round(vague_score, 1),
        f"{vague_hits} vague-word hit(s) in {wc} words",
    )

    bare = len(BARE_CLAIM.findall(prose))
    add(
        "absolute_security_claims",
        "precision",
        max(0.0, 100.0 - bare * 40),
        f"{bare} bare secure/unsafe claim(s)",
    )

    lists = extract_lists(prose)
    if lists:
        good = 0
        for lst in lists:
            n = len(lst)
            if 3 <= n <= 9:
                good += 1
            elif n < 3:
                good += 0  # should be prose
            else:
                good += 0  # too long flat
        add(
            "list_discipline",
            "structure",
            pct_score(good, len(lists)),
            f"{good}/{len(lists)} lists in 3–9 band",
        )
    else:
        add("list_discipline", "structure", 100.0, "no bullet lists")

    # section spine: enough body
    scount = len(sentences)
    if scount >= 2:
        spine = 100.0
        detail = f"{scount} sentences"
    elif scount == 1:
        spine = 60.0
        detail = "only 1 sentence"
    else:
        spine = 20.0 if text.strip() else 0.0
        detail = "stub / empty section"
    add("section_spine", "structure", spine, detail)

    rev = 100.0 if REVIEWER_TERMS.search(prose) else 40.0
    add(
        "reviewer_focus",
        "practicality",
        rev,
        "reviewer language present" if rev == 100 else "little reviewer focus language",
    )
    act = 100.0 if ACTIONABLE.search(prose) else 45.0
    add(
        "actionable_verbs",
        "practicality",
        act,
        "actionable language present" if act == 100 else "few action verbs",
    )

    return results


def score_chapter_file(
    path: Path,
    rubric: dict[str, Any],
    book_id: str = DEFAULT_BOOK,
) -> ChapterScore:
    raw = path.read_text(encoding="utf-8")
    meta, body = strip_front_matter(raw)
    title = meta.get("title") or path.stem
    tier = infer_tier(path, body, book_id)
    issues: list[str] = []

    # heading / fence rules
    fence_count = len(FENCE.findall(body))
    fence_ok = fence_count % 2 == 0
    if not fence_ok:
        issues.append("unbalanced code fences")

    headings = []
    in_fence = False
    for line in body.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^(#{1,6})\s+(.+)$", line)
        if m:
            headings.append((len(m.group(1)), m.group(2).strip()))

    heading_score = 100.0
    if headings:
        if headings[0][0] != 2:
            heading_score -= 40
            issues.append(f"first heading is h{headings[0][0]}, expected ##")
        if any(lvl == 1 for lvl, _ in headings):
            heading_score -= 40
            issues.append("contains # (h1) in body")
        prev = headings[0][0]
        for lvl, _ in headings[1:]:
            if lvl > prev + 1:
                heading_score -= 20
                issues.append("skipped heading level")
                break
            prev = lvl
    else:
        heading_score = 50.0
        issues.append("no headings in body")
    if not fence_ok:
        heading_score = min(heading_score, 40.0)
    heading_score = max(0.0, heading_score)

    file_checks: list[CheckResult] = [
        CheckResult(
            "heading_level_rules",
            "structure",
            heading_score,
            "; ".join(issues) if issues else "heading/fence rules ok",
            "chapter",
        )
    ]

    # action headings
    titled = [t for lvl, t in headings if lvl in (2, 3)]
    if titled:
        action_ok = sum(
            1 for t in titled if ACTION_START.search(t) or NOUN_OK.search(t)
        )
        file_checks.append(
            CheckResult(
                "action_headings",
                "structure",
                pct_score(action_ok, len(titled)),
                f"{action_ok}/{len(titled)} headings action/allowed",
                "chapter",
            )
        )
    else:
        file_checks.append(
            CheckResult(
                "action_headings", "structure", 50.0, "no ##/### headings", "chapter"
            )
        )

    fm_score = 100.0 if meta.get("title") else 40.0
    if meta.get("title") and not meta.get("description"):
        fm_score = 80.0
    file_checks.append(
        CheckResult(
            "front_matter",
            "structure",
            fm_score,
            "title+description" if fm_score == 100 else ("title only" if meta.get("title") else "missing title"),
            "chapter",
        )
    )

    # terminology: soft flag
    auth_mix = 0
    if re.search(r"\bauthentication\b.*\bauthorization\b|\bauthorization\b.*\bauthentication\b", body, re.I | re.S):
        # mixing in same chapter is ok if distinguished; penalize only "auth" alone abuse is hard—use light check
        auth_mix = 0
    encode_mix = len(
        re.findall(r"\b(encoding|escaping)\b.*\b(encoding|escaping)\b", body, re.I)
    )
    term_score = 100.0 if encode_mix < 3 else 70.0
    file_checks.append(
        CheckResult(
            "terminology_flags",
            "precision",
            term_score,
            "terminology ok" if term_score == 100 else "possible encode/escape mix",
            "chapter",
        )
    )

    # evidence / citation tier
    has_cwe = bool(CWE_OR_OWASP.search(body))
    has_refs = bool(
        re.search(r"^##\s+References\s*$", body, re.M) and REF_MARKER.search(body)
    )
    if tier == "B":
        cite_score = 100.0 if has_refs else (55.0 if REF_MARKER.search(body) else 30.0)
        cite_detail = "Tier B numbered refs ok" if has_refs else "Tier B missing ## References"
    else:
        # Tier A: vulnerability chapters should map standards; conceptual chapters softer
        is_vuln = bool(re.search(r"review-", path.name))
        if is_vuln:
            cite_score = 100.0 if has_cwe else 45.0
            cite_detail = "Tier A CWE/OWASP present" if has_cwe else "Tier A missing CWE/OWASP"
        else:
            cite_score = 90.0 if has_cwe or not is_vuln else 70.0
            cite_detail = "Tier A conceptual chapter"
    file_checks.append(
        CheckResult("citation_tier", "evidence", cite_score, cite_detail, "chapter")
    )

    is_vuln_chapter = bool(re.search(r"-\d+-review-|review-code-level|review-secure", path.name))
    std_score = 100.0 if (has_cwe or not is_vuln_chapter) else 40.0
    file_checks.append(
        CheckResult(
            "standard_mapping",
            "evidence",
            std_score,
            "standard mapping present" if has_cwe or not is_vuln_chapter else "no CWE/OWASP mapping",
            "chapter",
        )
    )

    # duplicate URLs
    urls = MD_LINK.findall(body)
    http_urls = [u for _, u in urls if u.startswith("http")]
    dup = len(http_urls) - len(set(http_urls))
    link_score = max(0.0, 100.0 - dup * 15)
    file_checks.append(
        CheckResult(
            "official_link_once",
            "evidence",
            link_score,
            f"{dup} duplicate URL(s)" if dup else "no duplicate http URLs",
            "chapter",
        )
    )

    # practicality: code examples
    fence_blocks = fence_count // 2
    expects_code = is_vuln_chapter or "review" in path.name
    if expects_code:
        if fence_blocks >= 2:
            code_score = 100.0
        elif fence_blocks == 1:
            code_score = 70.0
        else:
            code_score = 35.0
    else:
        code_score = 85.0 if fence_blocks >= 0 else 85.0
    file_checks.append(
        CheckResult(
            "code_or_payload_examples",
            "practicality",
            code_score,
            f"{fence_blocks} code block(s)",
            "chapter",
        )
    )

    # pedagogy
    prose = strip_code_fences(body)
    prose_wc = word_count(prose)
    code_lines = 0
    in_f = False
    for line in body.splitlines():
        if line.startswith("```"):
            in_f = not in_f
            continue
        if in_f:
            code_lines += 1
    if expects_code:
        if prose_wc < 80:
            tutorial_score = 40.0
        elif code_lines > prose_wc * 3:
            tutorial_score = 55.0
        else:
            tutorial_score = 95.0
    else:
        tutorial_score = 90.0 if prose_wc >= 100 else 60.0
    file_checks.append(
        CheckResult(
            "tutorial_not_reference_dump",
            "pedagogy",
            tutorial_score,
            f"{prose_wc} prose words / {code_lines} code lines",
            "chapter",
        )
    )

    if expects_code:
        if fence_blocks == 0:
            example_score = 30.0
        elif fence_blocks <= 12:
            example_score = 100.0
        else:
            example_score = 75.0  # very dense
    else:
        example_score = 80.0
    file_checks.append(
        CheckResult(
            "example_led",
            "pedagogy",
            example_score,
            f"{fence_blocks} examples",
            "chapter",
        )
    )

    durable_hits = len(DURABLE.findall(prose))
    durable_score = min(100.0, 40.0 + durable_hits * 8)
    file_checks.append(
        CheckResult(
            "durable_principles",
            "pedagogy",
            durable_score,
            f"{durable_hits} durable-concept hit(s)",
            "chapter",
        )
    )

    # focused scope: kitchen-sink titles
    kitchen = bool(
        re.search(r"\b(everything|complete guide|all about|introduction to)\b", title, re.I)
    )
    file_checks.append(
        CheckResult(
            "focused_scope_signal",
            "pedagogy",
            50.0 if kitchen else 95.0,
            "kitchen-sink title" if kitchen else "focused title",
            "chapter",
        )
    )

    if book_id == "hackers-mindset":
        file_checks.extend(score_hackers_mindset_structure(body))

    # section scores
    sections_raw = parse_sections(body)
    section_scores: list[SectionScore] = []
    for sec in sections_raw:
        # skip pure References mega-lists lightly
        checks = score_prose_block(sec["text"], level="section")
        # also fold chapter-level list check already in section
        cats = weighted_category_scores(checks, rubric)
        # fill missing categories with neutral 70 so overall not crushed
        for k in rubric["categories"]:
            if k not in cats or cats[k] == 0.0:
                # only fill if no checks in that category
                if not any(c.category == k for c in checks):
                    cats[k] = 70.0
        overall = overall_from_categories(cats, rubric)
        section_scores.append(
            SectionScore(
                heading=sec["heading"],
                level=sec["level"],
                start_line=sec["start_line"],
                word_count=word_count(sec["text"]),
                categories=cats,
                overall=overall,
                checks=checks,
            )
        )

    # chapter-level prose checks (whole body)
    chapter_prose_checks = score_prose_block(body, level="chapter")
    # dedupe: keep file_checks + chapter prose checks that are chapter-scoped
    all_chapter_checks = file_checks + [
        c
        for c in chapter_prose_checks
        if c.id
        in {
            "sentence_soft_limit",
            "sentence_hard_limit",
            "paragraph_soft_limit",
            "paragraph_hard_limit",
            "calm_tone",
            "vague_language",
            "absolute_security_claims",
            "list_discipline",
            "reviewer_focus",
            "actionable_verbs",
        }
    ]

    file_cats = weighted_category_scores(all_chapter_checks, rubric)
    for k in rubric["categories"]:
        if k not in file_cats:
            file_cats[k] = 70.0

    # word-weighted section mean
    if section_scores:
        tw = sum(max(s.word_count, 1) for s in section_scores)
        sec_cats: dict[str, float] = {}
        for k in rubric["categories"]:
            sec_cats[k] = round(
                sum(s.categories.get(k, 70.0) * max(s.word_count, 1) for s in section_scores)
                / tw,
                1,
            )
        sec_overall = overall_from_categories(sec_cats, rubric)
    else:
        sec_cats = file_cats
        sec_overall = overall_from_categories(file_cats, rubric)

    agg = rubric.get("aggregation", {})
    sw = float(agg.get("chapter_section_weight", 0.70))
    fw = float(agg.get("chapter_file_weight", 0.30))

    merged: dict[str, float] = {}
    for k in rubric["categories"]:
        merged[k] = round(sec_cats.get(k, 70.0) * sw + file_cats.get(k, 70.0) * fw, 1)

    overall = overall_from_categories(merged, rubric)
    # blend with sec_overall for stability
    overall = round(overall * 0.85 + sec_overall * 0.15, 1)

    rel = str(path.relative_to(ROOT)) if path.is_absolute() else str(path)
    return ChapterScore(
        path=rel,
        title=title,
        tier=tier,
        word_count=word_count(body),
        categories=merged,
        overall=overall,
        grade=grade_for(overall, rubric),
        sections=section_scores,
        checks=all_chapter_checks,
        issues=issues,
    )


def score_book(
    chapters: list[ChapterScore],
    rubric: dict[str, Any],
    scope: Path,
) -> dict[str, Any]:
    if not chapters:
        return {
            "overall": 0.0,
            "grade": "Weak",
            "categories": {},
            "checks": [],
            "chapter_count": 0,
        }

    mean_cats: dict[str, float] = {}
    for k in rubric["categories"]:
        mean_cats[k] = mean([c.categories.get(k, 0.0) for c in chapters])
    chapter_mean = mean([c.overall for c in chapters])

    # book checks
    index = scope / "index.md"
    nav_score = 100.0
    nav_detail = "index.md missing"
    if index.exists():
        text = index.read_text(encoding="utf-8")
        links = re.findall(r"\]\(([^)]+\.md)\)", text)
        missing = []
        for link in links:
            target = (index.parent / link).resolve()
            if not target.exists():
                missing.append(link)
        nav_score = 100.0 if not missing else max(0.0, 100.0 - len(missing) * 10)
        nav_detail = "all index links ok" if not missing else f"missing: {', '.join(missing[:5])}"

    weak = [c for c in chapters if c.overall < 70]
    coverage = max(0.0, 100.0 - len(weak) * (100.0 / max(len(chapters), 1)))
    read_mean = mean_cats.get("readability", 0.0)

    book_checks = [
        CheckResult("book_nav_consistency", "structure", nav_score, nav_detail, "book"),
        CheckResult(
            "book_coverage_balance",
            "pedagogy",
            round(coverage, 1),
            f"{len(weak)}/{len(chapters)} chapters below 70",
            "book",
        ),
        CheckResult(
            "book_mean_readability",
            "readability",
            read_mean,
            f"mean readability {read_mean}",
            "book",
        ),
    ]
    book_cats = weighted_category_scores(book_checks, rubric)
    for k in rubric["categories"]:
        if k not in book_cats:
            book_cats[k] = mean_cats.get(k, 70.0)

    agg = rubric.get("aggregation", {})
    bw = float(agg.get("book_chapter_weight", 0.80))
    cw = float(agg.get("book_corpus_weight", 0.20))
    merged = {
        k: round(mean_cats.get(k, 70.0) * bw + book_cats.get(k, 70.0) * cw, 1)
        for k in rubric["categories"]
    }
    overall = round(chapter_mean * bw + overall_from_categories(book_cats, rubric) * cw, 1)

    return {
        "overall": overall,
        "grade": grade_for(overall, rubric),
        "categories": merged,
        "chapter_mean": chapter_mean,
        "checks": [asdict(c) for c in book_checks],
        "chapter_count": len(chapters),
        "weak_chapters": [
            {"path": c.path, "overall": c.overall, "grade": c.grade} for c in weak
        ],
    }


def score_hackers_mindset_structure(body: str) -> list[CheckResult]:
    """Required sections for hackers-mindset pattern documents."""
    results: list[CheckResult] = []

    has_mitre = bool(
        re.search(r"^##\s+MITRE ATT&CK", body, re.M | re.I)
        or re.search(r"\bT\d{4}(\.\d{3})?\b", body)
    )
    results.append(
        CheckResult(
            "mitre_mapping_section",
            "evidence",
            100.0 if has_mitre else 25.0,
            "MITRE ATT&CK mapping present" if has_mitre else "missing MITRE ATT&CK mapping",
            "chapter",
        )
    )

    has_principles = bool(
        re.search(
            r"^##\s+Security principle violations",
            body,
            re.M | re.I,
        )
        or (
            re.search(r"\bCIA\b", body)
            and re.search(r"\bSTRIDE\b", body)
        )
    )
    results.append(
        CheckResult(
            "security_principles_section",
            "precision",
            100.0 if has_principles else 25.0,
            "CIA/STRIDE principles section present"
            if has_principles
            else "missing security principle violations section",
            "chapter",
        )
    )

    stage_hits = sum(
        1
        for label in (
            r"Stage\s+1\s*[—\-]\s*Prepare",
            r"Critical step",
            r"Stage\s+3\s*[—\-]\s*Execute",
            r"Attack stages",
        )
        if re.search(label, body, re.I)
    )
    stage_score = min(100.0, 25.0 * stage_hits)
    results.append(
        CheckResult(
            "attack_stages_playbook",
            "structure",
            stage_score if stage_hits else 20.0,
            f"stage playbook signals: {stage_hits}",
            "chapter",
        )
    )

    has_gallery = bool(
        re.search(r"^##\s+Same technique in other incidents", body, re.M | re.I)
        or re.search(r"incident gallery|other incidents", body, re.I)
    )
    results.append(
        CheckResult(
            "incident_gallery",
            "practicality",
            100.0 if has_gallery else 40.0,
            "incident gallery present" if has_gallery else "missing incident gallery",
            "chapter",
        )
    )

    has_key_preview = bool(
        re.search(r"Key violations\s*\(preview\)", body, re.I)
        or re.search(r"\*\*Key violations", body, re.I)
    )
    results.append(
        CheckResult(
            "key_violations_preview",
            "pedagogy",
            100.0 if has_key_preview else 45.0,
            "key violations preview in intro"
            if has_key_preview
            else "intro missing key violations preview",
            "chapter",
        )
    )

    return results


def discover_chapters(scope: Path, book_id: str = DEFAULT_BOOK) -> list[Path]:
    meta = BOOKS[book_id]
    files = sorted(scope.rglob("*.md"))
    out = []
    for f in files:
        rel = f.relative_to(scope)
        if f.name in meta["exclude_names"]:
            continue
        if any(part in meta["exclude_dir_names"] for part in rel.parts):
            continue
        if any(f.name.startswith(p) for p in meta["exclude_name_prefixes"]):
            continue
        out.append(f)
    return out


def chapter_to_dict(ch: ChapterScore, *, include_sections: bool = True) -> dict[str, Any]:
    d: dict[str, Any] = {
        "path": ch.path,
        "title": ch.title,
        "tier": ch.tier,
        "word_count": ch.word_count,
        "categories": ch.categories,
        "overall": ch.overall,
        "grade": ch.grade,
        "issues": ch.issues,
        "top_issues": sorted(
            (
                {"id": c.id, "category": c.category, "score": c.score, "detail": c.detail}
                for c in ch.checks
                if c.score < 80
            ),
            key=lambda x: x["score"],
        )[:8],
    }
    if include_sections:
        d["sections"] = [
            {
                "heading": s.heading,
                "level": s.level,
                "start_line": s.start_line,
                "word_count": s.word_count,
                "categories": s.categories,
                "overall": s.overall,
            }
            for s in ch.sections
        ]
    return d


def append_history(payload: dict[str, Any], book_id: str) -> None:
    paths = book_paths(book_id)
    paths["history_dir"].mkdir(parents=True, exist_ok=True)
    with paths["history_jsonl"].open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    paths["latest_json"].write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def read_history(book_id: str, limit: int = 20) -> list[dict[str, Any]]:
    path = book_paths(book_id)["history_jsonl"]
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows[-limit:]


def write_dashboard(
    latest: dict[str, Any],
    history: list[dict[str, Any]],
    book_id: str,
) -> None:
    paths = book_paths(book_id)
    label = BOOKS[book_id]["label"]
    book = latest.get("book", {})
    lines = [
        f"# Writing quality dashboard — {label}",
        "",
        f"_Updated {latest.get('timestamp', '')} · trigger `{latest.get('trigger', 'manual')}` · scope `{book_id}`_",
        "",
        "## Book score",
        "",
        f"**{book.get('overall', '—')} / 100** — {book.get('grade', '—')} "
        f"({book.get('chapter_count', 0)} chapters)",
        "",
        "| Category | Score |",
        "| --- | ---: |",
    ]
    for k, v in (book.get("categories") or {}).items():
        lines.append(f"| {k} | {v} |")

    lines += ["", "## Score history (recent)", ""]
    lines += [
        "| When | Trigger | Book | Δ | Chapters touched |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    prev = None
    for row in history:
        b = row.get("book", {}).get("overall")
        delta = ""
        if prev is not None and b is not None:
            d = round(b - prev, 1)
            delta = f"{d:+.1f}"
        prev = b
        touched = row.get("touched") or []
        touch_s = ", ".join(Path(p).name for p in touched[:4])
        if len(touched) > 4:
            touch_s += f" (+{len(touched) - 4})"
        lines.append(
            f"| {row.get('timestamp', '')} | {row.get('trigger', '')} | "
            f"{b if b is not None else '—'} | {delta or '—'} | {touch_s or 'full book'} |"
        )

    weak = book.get("weak_chapters") or []
    lines += ["", "## Chapters needing work (< 70)", ""]
    if not weak:
        lines.append("None — all scored chapters are ≥ 70.")
    else:
        lines += ["| Chapter | Score | Grade |", "| --- | ---: | --- |"]
        for w in weak:
            lines.append(f"| `{w['path']}` | {w['overall']} | {w['grade']} |")

    chapters = latest.get("chapters") or []
    lines += ["", "## All chapter scores", ""]
    lines += [
        "| Score | Grade | Tier | Chapter |",
        "| ---: | --- | --- | --- |",
    ]
    for ch in sorted(chapters, key=lambda c: c["overall"]):
        lines.append(
            f"| {ch['overall']} | {ch['grade']} | {ch.get('tier', '')} | `{ch['path']}` |"
        )

    lines += [
        "",
        "## How to read this",
        "",
        f"Scores are automated for **{label}** (`{book_id}`) against "
        "`tools/writing-eval/rubric.yaml`.",
        "",
        "- **Section** scores roll up into **chapter** scores (word-weighted).",
        "- **Chapter** scores roll up into the **book** score.",
        f"- History: `tools/writing-eval/history/{book_id}/scores.jsonl`",
        "",
        f"Re-run: `python3 tools/writing-eval/evaluate.py --scope {book_id}`",
        "",
    ]
    paths["dashboard_md"].write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_evaluation(
    paths: list[Path] | None,
    *,
    trigger: str,
    book_id: str | None = None,
    quiet: bool = False,
    full_book_when_partial: bool = True,
) -> dict[str, Any]:
    rubric = load_rubric()

    touched: list[str] = []
    selected: list[Path] = []
    rejected: list[str] = []

    if paths:
        inferred: set[str] = set()
        for p in paths:
            p = p.resolve()
            found = resolve_book(p)
            if found is None or not (p.is_file() and p.suffix == ".md"):
                rejected.append(str(p))
                continue
            inferred.add(found)
            selected.append(p)
            touched.append(str(p.relative_to(ROOT)))
        if rejected and not quiet:
            for r in rejected:
                print(
                    f"skip (outside supported books): {r}",
                    file=sys.stderr,
                )
        if not selected:
            raise SystemExit(
                "No paths under security-code-review or hackers-mindset; nothing to score."
            )
        if book_id is None:
            if len(inferred) > 1:
                raise SystemExit(
                    "Touched files span multiple books; pass --scope explicitly."
                )
            book_id = next(iter(inferred))
        elif any(resolve_book(p) != book_id for p in selected):
            raise SystemExit(f"Some paths are not under scope {book_id}.")
    else:
        book_id = book_id or DEFAULT_BOOK

    if book_id not in BOOKS:
        raise SystemExit(f"Unknown scope: {book_id}")

    scope = book_paths(book_id)["scope"]
    if not scope.is_dir():
        raise SystemExit(f"Book scope missing: {scope}")
    all_files = discover_chapters(scope, book_id)

    if paths:
        to_score = all_files if full_book_when_partial else selected
    else:
        to_score = all_files

    chapters = [score_chapter_file(p, rubric, book_id) for p in to_score]
    book = score_book(chapters, rubric, scope)
    book["scope"] = book_id
    book["label"] = BOOKS[book_id]["label"]

    payload = {
        "timestamp": utc_now(),
        "trigger": trigger,
        "scope": book_id,
        "rubric_version": rubric.get("version", 1),
        "touched": touched,
        "book": book,
        "chapters": [chapter_to_dict(c, include_sections=False) for c in chapters],
        "touched_detail": [
            chapter_to_dict(c, include_sections=True)
            for c in chapters
            if not touched or c.path in touched
        ],
    }
    if touched:
        payload["touched_detail"] = [
            chapter_to_dict(c, include_sections=True)
            for c in chapters
            if c.path in touched
        ]

    append_history(payload, book_id)
    history = read_history(book_id, 30)
    write_dashboard(payload, history, book_id)
    paths_out = book_paths(book_id)

    if not quiet:
        print(
            f"{BOOKS[book_id]['label']}: {book['overall']} / 100 ({book['grade']})"
        )
        if touched:
            for c in chapters:
                if c.path in touched:
                    print(f"  {c.overall:5.1f}  {c.grade:12}  {c.path}")
                    weak_checks = sorted(
                        (ch for ch in c.checks if ch.score < 80),
                        key=lambda x: x.score,
                    )[:5]
                    for ch in weak_checks:
                        print(f"      - [{ch.score:4.0f}] {ch.id}: {ch.detail}")
        else:
            weakest = sorted(chapters, key=lambda c: c.overall)[:8]
            print("Weakest chapters:")
            for c in weakest:
                print(f"  {c.overall:5.1f}  {c.grade:12}  {c.path}")
        print(f"History: {paths_out['history_jsonl']}")
        print(f"Dashboard: {paths_out['dashboard_md']}")

    return payload


def handle_hook_stdin() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print("writing-eval: invalid hook JSON", file=sys.stderr)
        return 0

    file_path = data.get("file_path") or data.get("path") or ""
    if not file_path:
        return 0

    p = Path(file_path)
    book_id = resolve_book(p)
    if book_id is None:
        return 0
    if p.name == "index.md":
        return 0

    payload = run_evaluation(
        [p],
        trigger="afterFileEdit",
        book_id=book_id,
        quiet=True,
    )
    book = payload["book"]
    touched = payload.get("touched_detail") or []
    msg = (
        f"writing-eval[{book_id}]: book {book['overall']} ({book['grade']})"
    )
    if touched:
        ch = touched[0]
        msg += f" | {Path(ch['path']).name} {ch['overall']} ({ch['grade']})"
    print(msg, file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Markdown files to highlight")
    parser.add_argument(
        "--scope",
        choices=sorted(BOOKS.keys()),
        help="Book to score (default: security-code-review, or inferred from paths)",
    )
    parser.add_argument("--hook-stdin", action="store_true", help="Cursor afterFileEdit mode")
    parser.add_argument("--history", action="store_true", help="Show recent history")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--touched-only",
        action="store_true",
        help="Score only given paths (skip full-book rollup)",
    )
    args = parser.parse_args(argv)

    if args.hook_stdin:
        return handle_hook_stdin()

    book_id = args.scope or DEFAULT_BOOK

    if args.history:
        rows = read_history(book_id, 20)
        dash = book_paths(book_id)["dashboard_md"]
        if not rows:
            print(f"No history yet for {book_id}.")
            return 0
        for row in rows:
            b = row.get("book", {})
            print(
                f"{row.get('timestamp')}  book={b.get('overall')}  "
                f"trigger={row.get('trigger')}  touched={len(row.get('touched') or [])}"
            )
        print(f"Dashboard: {dash}")
        return 0

    run_evaluation(
        list(args.paths) if args.paths else None,
        trigger="manual" if not args.paths else "manual-partial",
        book_id=args.scope,
        quiet=args.quiet,
        full_book_when_partial=not args.touched_only,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
