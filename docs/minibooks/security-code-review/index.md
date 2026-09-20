---
title: Security Code Review
keywords:
  - secure code review
  - secure coding
  - application security
description: Personal notes and articles about reviewing code for security issues.
---

## Security Code Review (WIP)

**Current version: 1.5**

### Overview

AI-assisted coding increases how much software ships and how fast it changes. Security code review still has to decide whether implementation can be abused—not only whether it works—and do that with enough evidence to stand behind.

The points below are the ideas this book uses again and again.

1. Working code is not the same as safe code; review asks what happens when input, identity, or environment is hostile.
2. Decomposition and data-flow tracing come before sink hunting: name the subsystem, trust boundary, and assumed control first.
3. Related bug classes share one review model; family chapters teach the model once, then variants and appendices supply density.
4. AI assistance scales hypothesis generation; humans still own validation, impact, and merge authority.
5. Defensible confidence means stating what was checked, what evidence supports it, and what risk remains.

After reading this book, we should be able to run a review from system map to code-level evidence, use AI without surrendering judgment, and explain findings in terms of abuse and impact.

## Version history

| Version | Date | What changed |
| --- | --- | --- |
| **1.5** | 2026-09-20 | Combined Part VI into one chapter: developers as primary reviewers; progressive skill + lightweight practice with AI assist. |
| **1.4** | 2026-09-20 | Shrunk Part V to two practical chapters (run AI-assisted review; keep it trustworthy). Removed experiment retelling and skills mini-chapter. Renumbered training/program to Ch8–9. |
| **1.3** | 2026-09-20 | Reorganized Part V (Ch6–9 + 6.1) around guided vs simple LLM review: measured process gains, six guided practices, skills as process encoding, deterministic floor / human gate. |
| **1.2** | 2026-09-20 | Renumbered chapters to match part order: Part IV = Ch5 (secure implementations), Part V = Ch6–9 (AI), Part VI = Ch10–11 (training/program). |
| **1.1** | 2026-09-20 | Writing-style retrofit: Overview + core concepts + we/us outcomes on hubs, spine, and family chapters; index voice; Verify checklist transitions. |
| **1.0** | 2026-09-20 | Consolidated Part IV from 7 topics into **3 family chapters** (identity/federation, tokens/API trust, transport/service identity) with a secure-implementations appendix. **Removed Part V (Chapter 11 platform configuration)** from this minibook. Renumbered AI assistance to Part V and training/governance to Part VI. |
| **0.9** | 2026-09-20 | Consolidated Part III from 42 mini-chapters into **10 family chapters** (XSS, interpreter injection, parsers, files, authz/session, SSRF/egress, disclosure/logging, crypto, secrets/APIs, supply chain); appendix grouped to match. |
| **0.8** | 2026-09-20 | Split Part III code density into an appendix: guiding mini-chapters keep definition, walkthrough, Python sample/fix, and verify; payloads, sinks, and multi-language catalogs move to [Appendix — Code-Level Reference](appendix/code-level-reference/index.md) with back-links from every chapter. |
| **0.7** | 2026-05-31 | Diversified code examples across all `review-*` sub-chapters: unique scenarios, endpoints, libraries, and sink APIs per section so the same snippet does not repeat across chapters—broader attack-surface coverage for readers. |
| **0.6** | 2026-05-31 | Added **attack payload** sections (and related abuse/misconfiguration examples) across all `review-*` sub-chapters—for inspiration during authorized testing and to show how flaws manifest in practice. Added **language-specific commands, functions, and APIs** (Python, Java, C#, JavaScript, HTML, Go, SQL, Shell, C) with short code samples per sink to enrich understanding of each vulnerability, not only generic patterns. |
| **0.5** | 2026-05-31 | Added Part IV (Chapter 5: OAuth, OIDC, JWT, SAML, TLS, mTLS, API signing) and Part V (Chapter 11: Snowflake, Databricks clean room, AWS IAM, Kubernetes, PostgreSQL). Renumbered AI assistance to Part VI and training/governance to Part VII. Added mini-chapter 4.42 (insecure coding practice). Standardized vulnerable-example language order (Python walkthrough; Java and C# first, then JS/HTML/Go/SQL/Shell/C when applicable). |
| **0.4** | 2026-05-31 | Split Chapter 4 into 40 code-level mini-chapters (4.1–4.41) with a shared review template: vulnerability characteristics, Python sample, step-by-step walkthrough, risk impact, multi-language examples, fix sections with library code, and official documentation references. Replaced the monolithic Chapter 4 body with a hub page and grouped MkDocs navigation. |
| **0.3** | 2026-05-17 | “Version 2” reorganization: 11 main chapters (0–9 + conclusion), action-oriented titles, reader-centered part summaries in the index. Merged tracing and business-logic review into Chapter 3 (System Decomposition Methodology). Consolidated code-level review into a single Chapter 4 overview; renumbered AI and program chapters (5–9). |
| **0.2** | 2026-05-13 | Editorial pass: removed per-chapter “Source References” sections pointing at the local archive; tightened cross-links. Added and applied the security code review writing style rule (short sentences, action headings, reader-centered intros). |
| **0.1** | 2026-05-13 | Initial minibook: preface, core chapters 0–11, conclusion, topic index, and *Secure Coding in Practice* reference article imported from materials. Separate chapters for manual methodology, data-flow tracing, business logic, and a single long code-level vulnerabilities chapter. |

## Preface

The preface states why classic review skill still matters when AI accelerates code production.

- [Why Security Code Review Skill Still Matters in the Age of AI](0-preface-why-security-code-review-skill-still-matters.md)

## Part I - Build the Reviewer Mindset

Part I builds the shared vocabulary: what security review is, and how we reduce uncertainty with trust boundaries and hostile assumptions.

- [1. Define Security Code Review](1-what-security-code-review-is.md)
- [2. Think Like a Security Reviewer](2-how-to-think-like-a-security-reviewer.md)

## Part II - Apply Security Review Methodology

Part II turns mindset into a map. We decompose the system into subsystems, then trace data across trust boundaries before opening random files.

- [3. System Decomposition Methodology](3-system-decomposition-methodology.md)

## Part III - Review Code-Level Vulnerabilities

Part III takes the methodology to the implementation layer. Ten **family** chapters teach how we review related bug classes; payloads and multi-language catalogs live in the [code-level appendix](appendix/code-level-reference/index.md).

- [4. Review Code-Level Vulnerabilities (overview)](4-review-code-level-vulnerabilities.md) — map and consolidation table
- [4.1 XSS](4-01-review-xss.md) · [4.2 Interpreter injection](4-02-review-interpreter-injection.md) · [4.3 Parsers](4-03-review-parsers-and-unsafe-reconstitution.md) · [4.4 Paths & files](4-04-review-paths-uploads-and-files.md) · [4.5 Authn / session / access](4-05-review-authentication-session-and-access.md)
- [4.6 SSRF & egress](4-06-review-ssrf-and-egress.md) · [4.7 Disclosure & logging](4-07-review-information-disclosure-and-logging.md) · [4.8 Cryptography](4-08-review-cryptography-in-application-code.md) · [4.9 Secrets & dangerous APIs](4-09-review-secrets-defaults-and-dangerous-apis.md) · [4.10 Supply chain](4-10-review-software-supply-chain.md)
- [Appendix — Code-Level Reference](appendix/code-level-reference/index.md)

## Part IV - Review Secure Implementations

Part IV reviews identity and transport implementations the way standards expect—not only whether a bug class exists in code. Three **family** chapters cover federation, tokens/API trust, and transport/service identity; dense catalogs live in the [secure-implementations appendix](appendix/secure-implementations-reference/index.md).

- [5. Review Secure Implementations (overview)](5-review-secure-implementations.md)
- [5.1 Identity & federation](5-01-review-identity-and-federation.md) · [5.2 Tokens & API trust](5-02-review-tokens-and-api-trust.md) · [5.3 Transport & service identity](5-03-review-transport-and-service-identity.md)
- [Appendix — Secure Implementations Reference](appendix/secure-implementations-reference/index.md)

## Part V - Scale With AI Assistance

Part V teaches how to run AI-assisted security code review and how to keep it trustworthy. AI accelerates summaries, hypotheses, and drafts. Humans still own validation and merge authority. Deterministic scanners stay the floor.

Companion talk: [Can LLMs do security code review?](../../talks/can-llms-do-security-code-review/index.md). For broader research trends and hybrid toolchains, see [Security Code Review Trends and Practices in the AI Era](../../essays/security-code-review-trend-and-practice-in-ai-era.md).

- [6. Run AI-Assisted Security Code Review](6-run-ai-assisted-security-code-review.md) — how to run the guided assist loop
- [7. Keep AI Review Trustworthy](7-keep-ai-review-trustworthy.md) — leads vs findings, failure modes, hybrid gates

## Part VI - Grow Capability and Governance

Part VI puts review skill where structural knowledge already lives: with developers. Train progressive security review, use AI under evidence gates, and keep lightweight ownership so coverage does not depend on a heroic AppSec bottleneck.

- [8. Enable Developers to Review Securely](8-enable-developers-to-review-securely.md)

## Conclusion

The conclusion ties the path together: review the code, explain the risk, test the evidence, and build defensible confidence.

- [Build Defensible Confidence](conclusion-from-uncertainty-to-defensible-confidence.md)

## Reference

The reference revisits secure coding examples that support the chapters.

- [Secure Coding in Practice](secure-coding-in-practice.md)
