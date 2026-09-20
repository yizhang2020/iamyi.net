---
title: AI Review Skills Research
keywords:
  - security code review
  - agent skills
  - Cursor skills
  - Claude Code skills
  - Trail of Bits
  - AI-assisted review
description: Research notes on public agent skills for security code review—methodology, architecture, and likely effectiveness compared to this book's review discipline.
---

## 5.1 - AI Review Skills Research

Agent **skills** are portable instruction packages—usually a `SKILL.md` file plus scripts, prompts, and reference docs—that tell an AI assistant how to run a multi-step workflow. Security review skills are a fast-moving area. This chapter catalogs notable public examples, summarizes their ideas and methodology, and discusses how they compare to the manual and hybrid review path in Chapters 3–4 and Part VI of this book.

This is a living research note. Add new skills as you discover them; compare each against evidence requirements, not marketing claims.

## What Is an Agent Skill for Security Review?

Most skills share the same skeleton:

| Element | Typical role |
| --- | --- |
| **YAML frontmatter** | `name`, `description`, optional `allowed-tools`, scope hints |
| **Orchestration instructions** | Phases, checklists, anti-patterns, when to stop |
| **Subagents or workers** | Parallel specialists (language, cluster, judge) |
| **Deterministic scripts** | Plan builders, SARIF emitters, indexers |
| **Artifact contract** | Findings as markdown/YAML, SARIF, or reports on disk |

Skills differ from a single chat prompt because they **encode process**: parameter collection, scope rules, deduplication, false-positive gates, and explicit partial-run handling.

Platforms that load skills include [Cursor](https://cursor.com/docs/skills), [Claude Code](https://code.claude.com/docs/en/skills), and plugin marketplaces such as [Trail of Bits skills](https://github.com/trailofbits/skills).

## How to Evaluate a Security Review Skill

Use the same skepticism you apply to a human reviewer or a scanner vendor.

| Question | Why it matters |
| --- | --- |
| **What is in scope?** | Language, diff-only vs full tree, kernel vs userspace, web vs native |
| **Who owns evidence?** | Worker, judge, human, or none |
| **How is scope enforced?** | `finding_scope_root` vs read-only `context_roots` prevents out-of-tree false positives |
| **Is output machine-readable?** | SARIF, structured frontmatter, or prose only |
| **Are false positives gated?** | Dedicated FP judge, severity filter, or raw model output |
| **Does it admit partial failure?** | Good skills surface incomplete worker runs; weak skills hide them in a polished report |
| **Does it align with your methodology?** | Decomposition, trust boundaries, and source-to-sink proof from Chapter 3 still apply |

**Likely effectiveness (rough tiers):**

- **High for triage and coverage** when skills combine clustered checklists, deterministic plans, and FP/dedup judges—especially on large C/C++ or diff review where humans miss volume.
- **Medium for novel business logic** unless the skill explicitly models adversarial scenarios and reads cross-file context.
- **Low as sole gate** for merge or release—treat skills as accelerators; humans (or hybrid CI with SAST) still own acceptance.

## Catalog of Public Skills (Starting Set)

| Skill | Source | Primary use | Maturity signal |
| --- | --- | --- | --- |
| **c-review** | [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/c-review) | Deep C/C++ memory-safety audit | Production-style orchestration, SARIF, judges |
| **differential-review** | [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/differential-review) | Security-focused PR/commit diff review | Phased methodology, blast radius, adversarial phase |
| **/security-review** (bundled) | [Claude Code](https://code.claude.com/docs/en/skills) | General security review command | Prompt-based; less artifact contract |
| **fp-check** | [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/fp-check) | False-positive verification gate | Complements finding generators |
| **static-analysis** | [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/static-analysis) | CodeQL, Semgrep, SARIF triage | Hybrid deterministic + LLM |
| **audit-context-building** | [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/audit-context-building) | Pre-audit architectural context | Upstream of deep review |

*Add rows as you evaluate more skills (Semgrep rules packs, custom Cursor skills, internal team playbooks exported as `SKILL.md`, etc.).*

---

## Case Study 1: Trail of Bits `c-review`

**Repository:** [plugins/c-review/skills/c-review/SKILL.md](https://github.com/trailofbits/skills/blob/main/plugins/c-review/skills/c-review/SKILL.md)

**Stated purpose:** Comprehensive C/C++ security review for memory corruption, integer overflow, race conditions, and platform-specific issues in userspace daemons and services.

### Core ideas

1. **Specialize by bug-class clusters** — Dozens of focused prompts (buffer writes, integer overflow, races, etc.) instead of one generic “find bugs” instruction.
2. **Separate finding scope from read scope** — Workers may read the whole repo for reachability but may only *file* findings inside `finding_scope_root`. That mirrors audit scoping in Chapter 3.
3. **Orchestrator + workers + judges** — Parallel workers write findings; dedup-judge merges duplicates; FP+severity judge filters and scores before `REPORT.md` and SARIF.
4. **Deterministic run plan** — `build_run_plan.py` selects clusters and renders spawn prompts so the model does not improvise missing fields (a common failure mode).
5. **Explicit anti-patterns** — The skill documents mistakes such as background worker spawns that break prompt-cache sharing, or skipping judges when zero findings are reported.

### Methodology (phases, condensed)

| Phase | What happens |
| --- | --- |
| 0 | Collect `threat_model`, model tier, severity filter, optional subtree scope |
| 1 | Probe language/platform flags (`is_cpp`, POSIX, Windows headers) |
| 2–3 | Create output dir; write `context.md` (purpose, scope, entry points, trust boundaries, hardening) |
| 4 | `build_run_plan.py` → `plan.json`, per-worker spawn files |
| 5–7 | Bookkeeping tasks; optional cache primer; parallel foreground workers; retry classifier |
| 8 | Dedup judge → FP/severity judge → SARIF safety net |
| 9 | Return `REPORT.md` + artifact index |

Threat models are explicit: `REMOTE`, `LOCAL_UNPRIVILEGED`, or `BOTH`—similar to choosing attacker position before review.

### Architecture (why it is interesting)

```text
coordinator → context.md + plan.json
           → parallel workers (cluster-specific prompts)
           → findings/*.md (YAML frontmatter + narrative sections)
           → dedup-judge → fp-judge → REPORT.md + REPORT.sarif
```

Workers exchange results through **files on disk**, not chat memory. That makes runs inspectable and diffable—closer to CI artifacts than a single opaque assistant transcript.

Finding records evolve in three stages: worker base fields → dedup metadata → `fp_verdict`, severity, exploitability on survivors.

### Approach compared to this book

| Book practice (Ch 3–4) | `c-review` alignment |
| --- | --- |
| Decompose system and name trust boundaries | Phase 3 `context.md` requires entry points and boundaries |
| Trace source → sink with evidence | Worker prompts target cluster-specific sinks; human still validates reachability |
| Attack payloads and language-specific APIs | Cluster prompts embed bug-class expertise; not identical to Part III mini-chapters |
| Human owns final judgment | FP judge reduces noise; human should still spot business-logic gaps |

### Possible effectiveness

**Strengths:** High coverage on native codebases; repeatable artifacts; strong handling of operational failures (partial runs, empty SARIF, malformed spawn prompts).

**Limits:** Not for managed languages (explicitly out of scope). Kernel and embedded bare-metal are excluded. Business-logic and authorization flaws need other skills or human review. Cost and time scale with worker count and model tier (`haiku` / `sonnet` / `opus`).

**Best fit:** Large C/C++ services, security audits with fixed scope, teams that already use SARIF or markdown findings in CI.

---

## Case Study 2: Trail of Bits `differential-review`

**Repository:** [plugins/differential-review/skills/differential-review/SKILL.md](https://github.com/trailofbits/skills/blob/main/plugins/differential-review/skills/differential-review/SKILL.md)

### Core ideas

- **Diff-first** — Optimized for PRs, commits, and regressions—not a full-repo first pass.
- **Risk-first triage** — Prioritizes auth, crypto, value transfer, and external calls.
- **Git history and blast radius** — Uses blame, caller impact, and test-coverage gaps to steer depth.
- **Adaptive depth** — Scales phases for SMALL / MEDIUM / LARGE codebases.
- **Adversarial phase for high-risk hunks** — Delegates attacker modeling and exploit scenarios when changes are sensitive.

### Methodology

Phases 0–6 plus pre-analysis: intake → changed-code analysis → test coverage → blast radius → deep context (Five Whys) → adversarial analysis → report. Supporting docs (`methodology.md`, `adversarial.md`, `reporting.md`, `patterns.md`) keep the main `SKILL.md` lean.

### Possible effectiveness

**Strengths:** Strong match for day-to-day PR review in mature repos; emphasizes regressions and evidence from git.

**Limits:** Less depth than `c-review` on exhaustive cluster coverage in unchanged lines; still needs human verification on logic flaws.

**Best fit:** Teams that want security review on every significant PR, especially when paired with SAST and Chapter 3 decomposition for risky subsystems.

---

## Case Study 3: Platform Bundled Skills (Claude Code)

**Reference:** [Claude Code skills](https://code.claude.com/docs/en/skills) — bundled commands such as `/code-review` and security-oriented workflows.

### Core ideas

- **Prompt-first orchestration** — The platform ships skills as detailed instructions; the model chooses tools dynamically.
- **Lower ceremony** — Fewer mandated artifacts than `c-review`; faster to start, less rigid contract.
- **Good for breadth** — General review across languages without maintaining cluster manifests.

### Possible effectiveness

**Strengths:** Low friction; useful for exploratory review and education.

**Limits:** Weaker guarantees on deduplication, FP rates, and partial-run visibility unless the team adds conventions.

**Best fit:** Ad hoc review, smaller changes, or as a complement to deterministic scanners—not as the only audit record for regulated releases.

---

## Case Study 4: Cursor Agent Skills (Ecosystem)

**Reference:** [Cursor Agent Skills](https://cursor.com/docs/skills)

### Core ideas

- Skills live under `.cursor/skills/`, `.agents/skills/`, or remote GitHub installs.
- `description` drives auto-selection; `paths` can scope skills to subtrees (useful in monorepos).
- `disable-model-invocation` forces explicit `/skill-name` for sensitive workflows.

Community examples (e.g. structured [code-review](https://github.com/bluriesophos/cursorskills) skills) often mirror human checklists: fetch diff, score design/security/tests, return prioritized issues.

### Possible effectiveness

**Strengths:** Easy to align with *this book’s* mini-chapter checklists—you can author a `review-stored-xss` skill that mirrors Chapter 4.1.

**Limits:** Quality varies by author; few ship FP judges or SARIF unless you build them.

**Best fit:** Teams standardized on Cursor who want repeatable *local* workflows tied to repo rules.

---

## Synthesis: Skills vs This Book’s Methodology

| Layer | This book | Typical agent skill |
| --- | --- | --- |
| **Intent** | Teach humans to read code with evidence | Automate phases of that reading |
| **Structure** | Parts II–IV decomposition + Part III patterns | Phases, workers, judges |
| **Output** | Reviewer notes, tests, defensible findings | `REPORT.md`, SARIF, finding files |
| **Governance** | Human acceptance | Skill success criteria + optional human sign-off |

Skills do not replace Chapter 3 decomposition or Chapter 4 source-to-sink discipline. They **encode** parts of that discipline when authors bake in scope, threat model, judges, and artifact contracts.

A practical stack:

1. **Subsystem framing** (Chapter 3) — what are we reviewing?
2. **Deterministic CI** — SAST, secrets, dependencies (Chapter 6, musings on hybrid review).
3. **Skill-assisted pass** — `differential-review` on the PR, `c-review` on native components, or a custom Cursor skill aligned with a 4.x mini-chapter.
4. **Human verification** — confirm exploitability, business rules, and fixes (Chapter 5 workflow).

## Research Backlog (Suggested Next Entries)

Add short case studies when you have time:

- **Trail of Bits `fp-check`** — systematic false-positive gate for other tools’ findings.
- **Trail of Bits `static-analysis`** — CodeQL/Semgrep + SARIF parsing skill.
- **Trail of Bits `variant-analysis`** — pattern-based hunt for similar bugs across repos.
- **OpenSSF / vendor “secure coding with AI” cheat sheets** — policy prompts, not full orchestration.
- **Internal team skills** — export your org’s review checklist as `SKILL.md` and compare maintainability.

When you add an entry, capture: source URL, scope, orchestration shape, artifact outputs, and one paragraph on **likely effectiveness** with honest limits.

## Reference

- [Trail of Bits skills marketplace](https://github.com/trailofbits/skills)
- [c-review SKILL.md](https://github.com/trailofbits/skills/blob/main/plugins/c-review/skills/c-review/SKILL.md)
- [differential-review SKILL.md](https://github.com/trailofbits/skills/blob/main/plugins/differential-review/skills/differential-review/SKILL.md)
- [Cursor — Agent Skills](https://cursor.com/docs/skills)
- [Claude Code — Skills](https://code.claude.com/docs/en/skills)
- [Security Code Review Trends and Practices in the AI Era](../../essays/security-code-review-trend-and-practice-in-ai-era.md) — hybrid human + scanner + LLM positioning for this book
