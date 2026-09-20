# Writing evaluation framework

Structured scoring for two topic books:

| Scope id | Path |
| --- | --- |
| `security-code-review` (default) | `docs/minibooks/security-code-review/**/*.md` |
| `hackers-mindset` | `docs/minibooks/hackers-mindset/**/*.md` |

**Out of scope:** musings, genai-ml-security, and all other docs.  
Hacker's Mindset also excludes `materials/` and `_template*`.

## Quick start

```bash
python3 tools/writing-eval/evaluate.py
python3 tools/writing-eval/evaluate.py --scope hackers-mindset
python3 tools/writing-eval/evaluate.py docs/minibooks/hackers-mindset/01-abuse-trusted-publish-pipeline.md
python3 tools/writing-eval/evaluate.py --history --scope hackers-mindset
```

## History

| Book | Directory |
| --- | --- |
| Security Code Review | `history/security-code-review/` |
| Hacker's Mindset | `history/hackers-mindset/` |

Each directory has `scores.jsonl`, `latest.json`, and `dashboard.md`.

## Score model

Same six categories and roll-up for both books. Hacker's Mindset adds structure checks for:

- MITRE ATT&CK mapping
- Security principle violations (CIA / STRIDE)
- Attack stages playbook
- Incident gallery
- Key violations preview in the intro

## Hook

`afterFileEdit` scores whichever supported book the edited file belongs to.
