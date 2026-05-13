---
title: Run Fully Automated LLM Review
keywords:
  - security code review
  - LLM security review
  - AI security
  - automated vulnerability detection
  - repository analysis
description: A chapter on how large language models can support fully automated security review and where such systems need guardrails.
---

## Chapter 8 - Run Fully Automated LLM Review

Large language models changed what automated review can attempt.

Traditional scanners are rule-driven. They look for patterns, data flows, unsafe APIs, and known vulnerable dependencies. LLM-based review can reason over names, comments, surrounding code, intent, and natural language context. That makes it useful for semantic review. It also makes it risky, because the model may sound confident when its reasoning is incomplete.

Fully automated LLM review should be treated as an analysis pipeline, not as an unquestioned authority.

## Define What LLM Review Can Do

An LLM can summarize code, identify suspicious data flows, generate attack hypotheses, explain a vulnerability, classify a finding, and propose a fix.

It can review examples such as SQL injection, command injection, SSRF, server-side template injection, XXE, broken access control, and insecure deserialization. These examples are useful because they require more explanation than simple pattern matching.

For example, a model may inspect an internal request helper and explain that attacker-controlled input can reach an internal route. It may then connect the pattern to SSRF and suggest an allowlist.

That is useful. But usefulness is not the same as correctness.

## Provide Repository-Wide Context

Security findings often depend on context outside the current file.

An LLM review system needs retrieval. It should gather routes, controllers, models, configuration, middleware, tests, and related helper functions. Without this context, the model may miss authorization checks in another layer or assume a missing check exists when it does not.

Repository-wide review should ask:

1. Where does input enter?
2. Where is authentication applied?
3. Where is authorization applied?
4. Where does data reach a sensitive sink?
5. What tests or policies prove the intended behavior?

The model can help connect these pieces, but the pipeline must provide the pieces.

## Use Specific Prompts and Structured Output

LLM review works better when the task is specific.

A weak prompt asks:

> Is this code secure?

A stronger prompt asks:

> Identify attacker-controlled input, sensitive sinks, missing trust-boundary checks, exploitability, impact, and a safe fix. Separate confirmed findings from hypotheses.

Structured output matters. A good automated review should return evidence:

- Source of input
- Sensitive sink
- Missing control
- Exploit scenario
- Confidence level
- Fix recommendation
- Test recommendation

This makes the result easier to triage and compare with SAST findings.

## Combine LLMs With Tools

LLMs should not work alone.

A better automated pipeline combines:

- SAST findings
- Dependency scan results
- Secret scan results
- Test coverage
- Code search and repository retrieval
- Threat model context
- LLM reasoning

The model can explain and prioritize tool output. It can also suggest missing cases that rule-based tools did not catch. But scanner evidence and code references should anchor the answer.

This reduces hallucination and makes the review more repeatable.

## Measure Effectiveness

Fully automated LLM review must be measured.

Useful questions include:

1. Did it find the issue?
2. Did it explain exploitability?
3. Did it identify the correct source and sink?
4. Did it produce a safe fix?
5. Did it hallucinate missing code?
6. Did it miss business context?
7. Did it create useful tests?

Benchmarks can include known vulnerable samples, CTF-style exercises, real historical bugs, and patched vulnerabilities from internal repositories.

The point is not to prove that the model is perfect. The point is to know where it helps and where it fails.

## Key Takeaway

LLM-based fully automated review can expand what automation can analyze.

It is useful for semantic reasoning, explanation, triage, and hypothesis generation. But it must be grounded in repository context, scanner evidence, structured prompts, and measurable results.

Treat fully automated LLM review as a powerful assistant pipeline. Do not treat it as final security authority.

## Source References

- `materials/book-security-code-review/book-outline.md`
- `materials/book-security-code-review/book-outline-code-examples.md`
- `docs/topics/security-code-review/secure-coding-in-practice.md`
