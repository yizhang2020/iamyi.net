---
title: Run AI-Assisted Security Code Review
keywords:
  - security code review
  - AI-assisted review
  - guided review
  - human in the loop
  - Cursor
description: How to run AI-assisted security code review—scope, prompts, habits, and a practical verification loop.
---

## Chapter 6 - Run AI-Assisted Security Code Review

### Overview

AI can speed security review. It summarizes changes, proposes abuse paths, drafts checklists, and shapes findings. It does not own the verdict. This chapter is a how-to: run an AI-assisted pass that inherits Parts II–IV—decomposition, source-to-sink tracing, and evidence—without treating fluent output as proof.

The points below are the ideas this chapter uses again and again.

1. Point AI at a named subsystem and trust boundary—not at unbounded dumps of code.

2. Use AI for summaries, hypotheses, checklists, and drafts; verify every claim in code.

3. Prefer guided prompts: stack, risks to check, source/sink/evidence, confirmed vs hypothesis.

4. Apply six working habits: specific questions, examples, limited files, coverage checks, deterministic known-bad rules, and deliberate depth.

5. Encode the loop in repo rules or agent skills so the next pass starts guided, not ad hoc.

After reading this chapter, we should be able to run a practical AI-assisted review pass and hand verified findings—or discarded leads—to the trustworthiness gate in Chapter 7.

## When to Use AI

Use AI when it reduces mechanical work so humans spend more time on judgment.

Good fits include pull-request summarization, entry-point discovery, attack-hypothesis brainstorming, control checklists for a known change type, draft finding structure, and first-pass test ideas.

Poor fits include “is this whole repository secure?”, merge gating on model comments alone, and accepting severity labels without reachability proof. Those cases belong under Chapter 7’s gates.

## Scope First

Start where Chapter 3 starts. Name the subsystem. Name the trust boundary. Name the change that crosses it.

Then ask the assistant to work **inside that frame**. Unscoped prompts invite shallow, high-confidence noise.

Useful opening asks:

- What files changed inside this boundary?
- What new entry points appeared?
- What authentication or authorization logic changed?
- What sensitive sinks or egress paths changed?
- What new dependencies or configuration values appeared?

The summary prepares better questions. It is not the finding.

## Use a Guided Prompt Pattern

Weak prompts ask whether the code is secure. Stronger prompts constrain the task.

A practical pattern:

1. State the stack and trust boundaries.

2. Name the risk classes to inspect (for example SSRF, IDOR, injection).

3. Ask for attacker-controlled input, sensitive sinks, and missing checks.

4. Require exploitability reasoning tied to code—not generic advice.

5. Separate **confirmed findings** (with file/line evidence) from **hypotheses**.

6. Ask for a concrete fix idea and an abuse-case test sketch.

Structured output helps triage. Prefer fields such as source, sink, missing control, exploit scenario, confidence, fix, and test.

## Six Working Habits

These habits keep AI assist useful.

**Ask specific questions.** Prefer “does this path check ownership before load?” over “find vulnerabilities.”

**Show good, bad, and ambiguous examples.** Put short snippets in the prompt or rule so the model is not inventing the standard.

**Review limited files at a time.** Whole-bundle prompts skip lines. File-by-file (or small batches) keeps attention.

**Confirm coverage.** After a pass, check that in-scope files were actually read and answered. Do not trust a confident summary as proof of coverage.

**Leverage deterministic knowledge.** Encode known-bad patterns as scanner rules, repo instructions, or scripts. Use them as the base layer under the model.

**Control pace.** Pause at suspicious patterns. Ask follow-ups. Process discipline beats raw model capability.

## Follow a Practical Loop

A simple AI-assisted review loop looks like this:

1. Name subsystem and trust boundary (Chapter 3).

2. Attach or invoke relevant repo rules / skills for language and risk class.

3. Ask for a scoped summary of the change.

4. Ask for attack hypotheses anchored to inputs and sinks.

5. Verify the highest-risk hypotheses in code—manually.

6. Ask for abuse-case tests; tighten them against real behavior.

7. Ask for a draft finding; rewrite every claim with cited evidence.

8. Promote only what survives verification (Chapter 7). Or discard the lead.

## Where Rules and Skills Fit

Repo instructions and agent skills are how teams encode this loop. Keep them short and high-signal: approved libraries, banned APIs, auth rules, secrets handling, logging rules, and test expectations.

Public skill packs and platform skills can help with orchestration. Evaluate them by whether they demand evidence, enforce scope, and admit partial failure—not by demo polish. For a companion framing of guided vs ad-hoc review, see [Can LLMs do security code review?](../../talks/can-llms-do-security-code-review/index.md). For hybrid toolchain context, see [Security Code Review Trends and Practices in the AI Era](../../essays/security-code-review-trend-and-practice-in-ai-era.md).

## Keep It Practical for Small Teams

Small teams can still run the loop.

- Deterministic scanners for secrets, dependencies, and baseline SAST
- Guided AI on prioritized paths and risky pull requests
- Human review for authentication, authorization, cryptography, deserialization, command execution, uploads, multi-tenant isolation, and public sensitive endpoints
- Documented accepted risk when coverage is incomplete

The goal is not perfect review of every commit. The goal is a repeatable path from informal reading to evidence-backed decisions.

## Key Takeaway

AI-assisted security code review works when AI accelerates a **guided** process.

Scope the boundary. Prompt for evidence. Limit greed. Verify in code. Encode known-bad patterns deterministically. Let humans own exploitability and priority.

Chapter 7 covers the trustworthiness gate: leads versus findings, failure modes, and hybrid merge posture.
