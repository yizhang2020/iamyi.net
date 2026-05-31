---
title: Review Code-Level Vulnerabilities
keywords:
  - security code review
  - secure coding
  - injection
  - path traversal
  - deserialization
  - code-level analysis
description: Overview of code-level security review and an index of focused mini-chapters for each vulnerability family.
---

## Chapter 4 - Review Code-Level Vulnerabilities

Code-level security analysis is the final layer of the methodology.

The methodology chapter defined structure, modeled subsystem threats, traced data, and checked business logic. This part moves into the code that implements the security controls. The reviewer now asks how individual variables, functions, libraries, parsers, and framework calls can turn attacker-controlled input into security impact.

The goal is not to memorize every bug class. The goal is to learn a repeatable pattern: trace the data, identify the trust boundary, find the unsafe assumption, and verify the control.

## How to Use the Mini-Chapters

Each vulnerability family below has its own standalone chapter. Every mini-chapter follows the same teaching pattern:

1. **What the flaw is** — definition and CWE mapping where applicable.
2. **Vulnerability characteristics** — where the pattern appears in real codebases (features, sinks, weak controls).
3. **Sample vulnerable code in Python** — one focused example to study first.
4. **Step-by-step review walkthrough** — how to trace the flaw and why each step matters.
5. **Risk impact analysis** — what can go wrong for users, data, and the business.
6. **Vulnerable examples in other languages** — always **Java** and **C#** first; then, when applicable, **JavaScript**, **HTML**, and **Go**; then **SQL**, **Shell**, and **C**. The **Sample Vulnerable Code** section always uses **Python** for the primary walkthrough.
7. **Fix: safer patterns and libraries** — real code using vetted APIs, with **Important** notes per language.
8. **Verify during review** — evidence to collect before you file a finding.
9. **Reference** — official documentation links for the libraries and standards cited in the fix section.

The archive article [Secure Coding in Practice](secure-coding-in-practice.md) remains available as background reading; mini-chapters do not link to it in their reference sections.

## Input Validation, Injection, and Parsing

- [4.1 Review Stored XSS](4-01-review-stored-xss.md)
- [4.2 Review Reflected XSS](4-02-review-reflected-xss.md)
- [4.3 Review SQL Injection](4-03-review-sql-injection.md)
- [4.4 Review Command Injection](4-04-review-command-injection.md)
- [4.5 Review Code Injection](4-05-review-code-injection.md)
- [4.6 Review JSON Injection](4-06-review-json-injection.md)
- [4.7 Review Dynamic JSP Inclusion](4-07-review-dynamic-jsp-inclusion.md)
- [4.8 Review XXE](4-08-review-xxe.md)
- [4.9 Review SSTI](4-09-review-ssti.md)
- [4.10 Review Path Traversal](4-10-review-path-traversal.md)
- [4.11 Review Client-Side Validation](4-11-review-client-side-validation.md)

## Cryptography

- [4.12 Review Cryptographic Implementation](4-12-review-cryptographic-implementation.md)

## Sessions, Requests, and Access Control

- [4.13 Review CSRF](4-13-review-csrf.md)
- [4.14 Review SSRF](4-14-review-ssrf.md)
- [4.15 Review Broken Session Management](4-15-review-broken-session-management.md)
- [4.16 Review JWT Security](4-16-review-jwt-security.md)
- [4.17 Review Authentication and Authorization](4-17-review-authentication-and-authorization.md)
- [4.18 Review Broken Password Lifecycle](4-18-review-broken-password-lifecycle.md)
- [4.19 Review Forced Browsing](4-19-review-forced-browsing.md)
- [4.20 Review IDOR](4-20-review-idor.md)

## Information Disclosure

- [4.21 Review Error Page Disclosure](4-21-review-error-page-disclosure.md)
- [4.22 Review Sensitive Data in URL](4-22-review-sensitive-data-in-url.md)
- [4.23 Review Username Enumeration](4-23-review-username-enumeration.md)
- [4.24 Review Internal and Egress Exfiltration](4-24-review-internal-and-egress-exfiltration.md)
- [4.25 Review Sensitive Logging](4-25-review-sensitive-logging.md)

## File and Path Handling

- [4.26 Review Insecure Temporary Files](4-26-review-insecure-temporary-files.md)
- [4.27 Review Insecure File Parsing](4-27-review-insecure-file-parsing.md)
- [4.28 Review Insecure File Path Handling](4-28-review-insecure-file-path-handling.md)
- [4.29 Review Insecure File Upload](4-29-review-insecure-file-upload.md)

## Framework and Configuration

- [4.30 Review Framework Secure Defaults](4-30-review-framework-secure-defaults.md)

## Insecure Coding Practices

- [4.41 Review Insecure Coding Practice](4-41-review-insecure-coding-practice.md) — TLS verification, JWT signature/key handling, cookie flags, and related habits
- [4.31 Review Sensitive Code Comments](4-31-review-sensitive-code-comments.md)
- [4.32 Review Hardcoded Secrets](4-32-review-hardcoded-secrets.md)
- [4.33 Review Insecure Cookie Configuration](4-33-review-insecure-cookie-configuration.md)
- [4.34 Review Obsolete Code](4-34-review-obsolete-code.md)
- [4.35 Review Dangerous Functions](4-35-review-dangerous-functions.md)
- [4.36 Review Non-Standard Crypto Practices](4-36-review-non-standard-crypto-practices.md)
- [4.37 Review Insecure Deserialization](4-37-review-insecure-deserialization.md)
- [4.38 Review Encryption and Decryption Mistakes](4-38-review-encryption-decryption-mistakes.md)

## Logging and Supply Chain

- [4.39 Review Secure Logging](4-39-review-secure-logging.md)
- [4.40 Review Software Supply Chain](4-40-review-software-supply-chain.md)

## Core Review Habits

Most code-level findings still start with data flow:

- Where does the data come from?
- What code transforms it?
- Where is it used (the sink)?
- Is the data attacker-controlled?

Separate **input validation** from **output encoding**. Validation decides whether data is acceptable for the application. Encoding makes data safe for a specific output context (HTML, SQL, shell, URL).

When you finish a mini-chapter, record source, sink, missing control, impact, and a test that proves the fix.

## Next: Secure Implementations and Configuration

After code-level patterns, continue with:

- [Chapter 10 - Review Secure Implementations](10-review-secure-implementations.md) — OAuth, OIDC, JWT, SAML, TLS, mTLS, API signing
- [Chapter 11 - Review Secure Configuration](11-review-secure-configuration.md) — Snowflake, Databricks clean rooms, AWS IAM, Kubernetes, PostgreSQL
