---
title: Use AI to Assist Human Review
keywords:
  - security code review
  - AI-assisted review
  - human in the loop
  - secure code review workflow
  - Cursor
description: A chapter on practical human-in-the-loop workflows where AI helps security reviewers move faster without replacing judgment.
---

## Chapter 7 - Use AI to Assist Human Review

The most practical use of AI in security review is not full replacement.

It is assistance.

AI can summarize code, generate review questions, trace possible data flows, explain unfamiliar frameworks, draft findings, and suggest tests. The human reviewer still decides whether the issue is real, exploitable, and worth fixing.

This workflow is especially useful in small teams, fast-moving product groups, and large repositories where no reviewer can manually read everything.

## Start With Context Summarization

A reviewer often loses time just understanding the change.

AI can help by summarizing a pull request:

- What files changed?
- What new entry points were added?
- What sensitive operations changed?
- What authentication or authorization logic changed?
- What new dependencies or configuration values were introduced?

This does not find the vulnerability by itself. It prepares the reviewer to ask better questions.

## Generate Attack Hypotheses

AI is useful for brainstorming abuse paths.

For an SSRF-like code path, the reviewer can ask:

- What input is attacker-controlled?
- What internal resource could be reached?
- Can redirects or encoded addresses bypass filtering?
- Is a denylist enough?
- What allowlist would be safer?
- What tests should be added?

For an IDOR-like code path, the reviewer can ask:

- What object does the user select?
- Where is ownership checked?
- Can one authenticated user access another user's data?
- Is tenant isolation enforced?

The reviewer should treat these as hypotheses. Each hypothesis must be verified against the code.

## Use AI for Checklists and Tests

AI can turn a code change into a focused checklist.

For a password reset change, it may suggest checking token randomness, expiration, single-use behavior, response consistency, rate limiting, logging, and email delivery assumptions.

For a file handling change, it may suggest checking path normalization, base-directory enforcement, file type validation, temporary file handling, permissions, and cleanup.

AI can also draft abuse-case tests. A human reviewer should refine them so they match the system's real behavior.

## Draft Findings, Then Verify Them

AI can help write clear findings.

A good finding needs source, sink, missing control, impact, proof, recommended fix, and test evidence. AI can organize that structure quickly.

But the reviewer must verify every claim. AI may invent a missing function, misunderstand a framework, or overstate impact. A finding should not be submitted unless the reviewer can point to code evidence.

The human role is to turn AI output into defensible security judgment.

## Follow a Practical Workflow

A simple AI-assisted review workflow looks like this:

1. Ask AI to summarize the change.
2. Ask AI to identify security-sensitive files and trust boundaries.
3. Ask AI to generate attack hypotheses.
4. Manually verify the highest-risk hypotheses.
5. Ask AI to suggest abuse-case tests, then review and edit them.
6. Ask AI to draft the finding, then rewrite it with verified evidence.

This workflow keeps AI useful but bounded.

## Keep the Workflow Practical for Small Teams

Small companies often do not have a full AppSec team.

AI-assisted review can help them build a lightweight program. They can use automated scanners for baseline coverage, AI for summarization and hypothesis generation, and human review for sensitive changes.

The goal is not perfect review of every commit. The goal is a practical path:

- Prioritize risky code paths.
- Use automation for common patterns.
- Use AI to reduce review time.
- Keep humans responsible for final decisions.
- Document accepted risk.

This is often enough to move from informal review to repeatable security practice.

## Key Takeaway

AI-assisted human review works best when AI accelerates the reviewer, not when it replaces the reviewer.

Let AI summarize, suggest, classify, and draft. Let humans verify context, exploitability, ownership, and risk.

The best result is faster review with clearer evidence.

## Source References

- `materials/book-security-code-review/book-outline.md`
- `materials/book-security-code-review/book-outline-code-examples.md`
- `docs/topics/security-code-review/secure-coding-in-practice.md`
