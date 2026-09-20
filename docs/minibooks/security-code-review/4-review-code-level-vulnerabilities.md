---
title: Review Code-Level Vulnerabilities
keywords:
  - security code review
  - secure coding
  - injection
  - path traversal
  - deserialization
  - code-level analysis
description: Overview of code-level security review—ten family chapters plus a code-density appendix.
---

## Chapter 4 - Review Code-Level Vulnerabilities

### Overview

Code-level security analysis is the final layer of the methodology. Earlier chapters defined structure, modeled subsystem threats, traced data, and checked business logic. This part asks how variables, functions, libraries, parsers, and framework calls turn attacker-controlled input into security impact.

The goal is not to memorize every CWE. The points below are the ideas Part III uses again and again.

1. Trace data from source to sink across a trust boundary before labeling a bug class.
2. Related vulnerabilities share one failure model; learn the model once, then adjust sources and sinks per variant.
3. Separate input validation from output encoding (or parameterization) at the right context.
4. Record source, sink, missing control, impact, and a test that would prove a fix.
5. Keep dense payloads and multi-language catalogs in the appendix so guiding chapters stay readable.

After reading this overview and the family chapters, we should be able to review a code change by family, produce evidence-backed findings, and know when to open the appendix for density.

## Ten Family Chapters (Consolidated)

Former forty-two mini-chapters are grouped into **ten families**. Each family shares one review model, lists variants with where-to-look tables, walks one primary example, and points to the appendix for payloads and multi-language catalogs.

| # | Family | Former mini-chapters (examples) |
| --- | --- | --- |
| [4.1](4-01-review-xss.md) | XSS | Stored, reflected, DOM |
| [4.2](4-02-review-interpreter-injection.md) | Interpreter injection | SQL, command, code, JSON, SSTI |
| [4.3](4-03-review-parsers-and-unsafe-reconstitution.md) | Parsers & reconstitution | XXE, dynamic JSP include, deserialization |
| [4.4](4-04-review-paths-uploads-and-files.md) | Paths, uploads & files | Path traversal, upload, temp files, parsing |
| [4.5](4-05-review-authentication-session-and-access.md) | Authn, session & access | CSRF, session, IDOR, JWT (code-level), cookies |
| [4.6](4-06-review-ssrf-and-egress.md) | SSRF & egress | SSRF, internal/egress exfiltration |
| [4.7](4-07-review-information-disclosure-and-logging.md) | Disclosure & logging | Errors, URLs, enumeration, logging, comments |
| [4.8](4-08-review-cryptography-in-application-code.md) | Cryptography | Implementation, non-standard crypto, enc/dec mistakes |
| [4.9](4-09-review-secrets-defaults-and-dangerous-apis.md) | Secrets, defaults & APIs | Secrets, dangerous functions, defaults, client-only validation |
| [4.10](4-10-review-software-supply-chain.md) | Supply chain | Dependencies and build trust |

## How to Use a Family Chapter

The sequence below is the same for every family chapter.

1. **Shared model** — the review question for the whole family.
2. **Variants** — short definitions and where-to-look tables (former mini-topics).
3. **Worked example** — one Python sample and step-by-step walkthrough.
4. **Risk, fix principles, verify** — family-level evidence habits.
5. **Appendix pointer** — payloads, sinks, and multi-language fixes.

## Code-Level Appendix

Open the [Appendix — Code-Level Reference](appendix/code-level-reference/index.md) when density is needed. Each family has one appendix page with subsections for every former mini-chapter. Guiding chapters and appendix pages link both ways.

The archive article [Secure Coding in Practice](secure-coding-in-practice.md) remains available as background reading.

## Core Review Habits

Most code-level findings still start with data flow. The questions below keep the review grounded.

- Where does the data come from?
- What code transforms it?
- Where is it used (the sink)?
- Is the data attacker-controlled?

Separate **input validation** from **output encoding**. Validation decides whether data is acceptable for the application. Encoding makes data safe for a specific output context (HTML, SQL, shell, URL).

When we finish a family chapter, we should be able to record source, sink, missing control, impact, and a test that proves the fix.

## Next: Secure Implementations

After code-level patterns, continue with [Chapter 5 - Review Secure Implementations](5-review-secure-implementations.md)—identity and federation, tokens and API trust, and transport and service identity.
