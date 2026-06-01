---
title: Security Code Review
keywords:
  - secure code review
  - secure coding
  - application security
description: Personal notes and articles about reviewing code for security issues.
---

## Security Code Review (WIP)

**Current version: 0.6**

Use this topic as a practical guide to security code review, with a focus on manual review skill and AI-assisted review.

## Version history

| Version | Date | What changed |
| --- | --- | --- |
| **0.6** | 2026-05-31 | Added **attack payload** sections (and related abuse/misconfiguration examples) across all `review-*` sub-chapters—for inspiration during authorized testing and to show how flaws manifest in practice. Added **language-specific commands, functions, and APIs** (Python, Java, C#, JavaScript, HTML, Go, SQL, Shell, C) with short code samples per sink to enrich understanding of each vulnerability, not only generic patterns. |
| **0.5** | 2026-05-31 | Added Part IV (Chapter 10: OAuth, OIDC, JWT, SAML, TLS, mTLS, API signing) and Part V (Chapter 11: Snowflake, Databricks clean room, AWS IAM, Kubernetes, PostgreSQL). Renumbered AI assistance to Part VI and training/governance to Part VII. Added mini-chapter 4.41 (insecure coding practice). Standardized vulnerable-example language order (Python walkthrough; Java and C# first, then JS/HTML/Go/SQL/Shell/C when applicable). |
| **0.4** | 2026-05-31 | Split Chapter 4 into 40 code-level mini-chapters (4.1–4.40) with a shared review template: vulnerability characteristics, Python sample, step-by-step walkthrough, risk impact, multi-language examples, fix sections with library code, and official documentation references. Replaced the monolithic Chapter 4 body with a hub page and grouped MkDocs navigation. |
| **0.3** | 2026-05-17 | “Version 2” reorganization: 11 main chapters (0–9 + conclusion), action-oriented titles, reader-centered part summaries in the index. Merged tracing and business-logic review into Chapter 3 (System Decomposition Methodology). Consolidated code-level review into a single Chapter 4 overview; renumbered AI and program chapters (5–9). |
| **0.2** | 2026-05-13 | Editorial pass: removed per-chapter “Source References” sections pointing at the local archive; tightened cross-links. Added and applied the security code review writing style rule (short sentences, action headings, reader-centered intros). |
| **0.1** | 2026-05-13 | Initial minibook: preface, core chapters 0–11, conclusion, topic index, and *Secure Coding in Practice* reference article imported from materials. Separate chapters for manual methodology, data-flow tracing, business logic, and a single long code-level vulnerabilities chapter. |

## Preface

This preface helps you see why security code review remains important as AI-assisted coding changes how software is written.

- [Why Security Code Review Skill Still Matters in the Age of AI](0-preface-why-security-code-review-skill-still-matters.md)

## Part I - Build the Reviewer Mindset

This part helps you build the basic reviewer mindset. You will learn how security review uses trust boundaries, attacker-controlled input, and uncertainty reduction to reason about code.

- [1. Define Security Code Review](1-what-security-code-review-is.md)
- [2. Think Like a Security Reviewer](2-how-to-think-like-a-security-reviewer.md)

## Part II - Apply Security Review Methodology

This part helps you break a system into reviewable subsystems. You will use business logic, authentication, authorization, and data-flow tracing to define boundaries and prepare for code-level review.

- [3. System Decomposition Methodology](3-system-decomposition-methodology.md)

## Part III - Review Code-Level Vulnerabilities

This part takes the methodology down to the final implementation layer. Start with the chapter overview, then open the mini-chapter that matches the code you are reviewing. Each mini-chapter teaches how to read the code, how to phrase an LLM checklist, and which safer libraries apply in Java, Python, C#, and Go.

- [4. Review Code-Level Vulnerabilities (overview)](4-review-code-level-vulnerabilities.md)

**Input, injection, and parsing:** [4.1 Stored XSS](4-01-review-stored-xss.md) · [4.2 Reflected XSS](4-02-review-reflected-xss.md) · [4.3 SQL Injection](4-03-review-sql-injection.md) · [4.4 Command Injection](4-04-review-command-injection.md) · [4.5 Code Injection](4-05-review-code-injection.md) · [4.6 JSON Injection](4-06-review-json-injection.md) · [4.7 Dynamic JSP Inclusion](4-07-review-dynamic-jsp-inclusion.md) · [4.8 XXE](4-08-review-xxe.md) · [4.9 SSTI](4-09-review-ssti.md) · [4.10 Path Traversal](4-10-review-path-traversal.md) · [4.11 Client-Side Validation](4-11-review-client-side-validation.md)

**Cryptography:** [4.12 Cryptographic Implementation](4-12-review-cryptographic-implementation.md)

**Sessions and access control:** [4.13 CSRF](4-13-review-csrf.md) · [4.14 SSRF](4-14-review-ssrf.md) · [4.15 Broken Session Management](4-15-review-broken-session-management.md) · [4.16 JWT Security](4-16-review-jwt-security.md) · [4.17 Authentication and Authorization](4-17-review-authentication-and-authorization.md) · [4.18 Broken Password Lifecycle](4-18-review-broken-password-lifecycle.md) · [4.19 Forced Browsing](4-19-review-forced-browsing.md) · [4.20 IDOR](4-20-review-idor.md)

**Information disclosure:** [4.21 Error Page Disclosure](4-21-review-error-page-disclosure.md) · [4.22 Sensitive Data in URL](4-22-review-sensitive-data-in-url.md) · [4.23 Username Enumeration](4-23-review-username-enumeration.md) · [4.24 Internal and Egress Exfiltration](4-24-review-internal-and-egress-exfiltration.md) · [4.25 Sensitive Logging](4-25-review-sensitive-logging.md)

**File handling:** [4.26 Insecure Temporary Files](4-26-review-insecure-temporary-files.md) · [4.27 Insecure File Parsing](4-27-review-insecure-file-parsing.md) · [4.28 Insecure File Path Handling](4-28-review-insecure-file-path-handling.md) · [4.29 Insecure File Upload](4-29-review-insecure-file-upload.md)

**Framework and insecure practices:** [4.41 Insecure Coding Practice](4-41-review-insecure-coding-practice.md) (TLS verify, JWT, cookies) · [4.30 Framework Secure Defaults](4-30-review-framework-secure-defaults.md) · [4.31 Sensitive Code Comments](4-31-review-sensitive-code-comments.md) · [4.32 Hardcoded Secrets](4-32-review-hardcoded-secrets.md) · [4.33 Insecure Cookie Configuration](4-33-review-insecure-cookie-configuration.md) · [4.34 Obsolete Code](4-34-review-obsolete-code.md) · [4.35 Dangerous Functions](4-35-review-dangerous-functions.md) · [4.36 Non-Standard Crypto](4-36-review-non-standard-crypto-practices.md) · [4.37 Insecure Deserialization](4-37-review-insecure-deserialization.md) · [4.38 Encryption Mistakes](4-38-review-encryption-decryption-mistakes.md)

**Logging and supply chain:** [4.39 Secure Logging](4-39-review-secure-logging.md) · [4.40 Software Supply Chain](4-40-review-software-supply-chain.md)

## Part IV - Review Secure Implementations

This part helps you review identity and transport implementations the way standards expect—not only whether a bug class exists in code. You will walk OAuth, OpenID Connect, JWT, SAML, TLS, mTLS, and API signing with the same evidence discipline as Part III.

- [10. Review Secure Implementations (overview)](10-review-secure-implementations.md)

**Identity and federation:** [10.1 OAuth 2.0](10-01-review-oauth-implementation.md) · [10.2 OpenID Connect](10-02-review-oidc-implementation.md) · [10.3 JWT Implementation](10-03-review-jwt-implementation.md) · [10.4 SAML](10-04-review-saml-federation.md)

**Transport and API trust:** [10.5 TLS and SSL Protocol](10-05-review-tls-ssl-protocol.md) · [10.6 mTLS](10-06-review-mtls-service-identity.md) · [10.7 API Keys and Signing](10-07-review-api-keys-and-request-signing.md)

## Part V - Review Secure Configuration

This part helps you review platform and data-plane configuration when security depends on grants, network rules, and sharing boundaries—not only application logic.

- [11. Review Secure Configuration (overview)](11-review-secure-configuration.md)

- [11.1 Snowflake](11-01-review-snowflake-security-configuration.md) · [11.2 Databricks Clean Room](11-02-review-databricks-clean-room-configuration.md) · [11.3 AWS IAM and Secrets](11-03-review-aws-iam-and-secrets-configuration.md) · [11.4 Kubernetes](11-04-review-kubernetes-security-configuration.md) · [11.5 PostgreSQL](11-05-review-postgresql-security-configuration.md)

## Part VI - Scale With AI Assistance

This part scales what you practiced in Parts II–V—decomposition, tracing, code-level controls, implementations, and configuration—rather than swapping that order for brittle prompt magic. Artificial intelligence amplifies reviewers when tasks are constrained: summarized context, structured attack hypotheses, and evidence checks against concrete sources, sinks, and policies. Teams still need deterministic gates, calibrated trust in model output, and explicit governance so tooling does not outrun judgment.

You can go deeper on research trends and a typical hybrid toolchain in [Security Code Review Trends and Practices in the AI Era](../../security-musings/security-code-review-trend-and-practice-in-ai-era.md).

- [5. Use AI to Assist Human Review](5-use-ai-to-assist-human-review.md)
- [6. Run Fully Automated LLM Review](6-run-fully-automated-llm-review.md)
- [7. Control the Risks of AI Review](7-control-the-risks-of-ai-review.md)

## Part VII - Grow Capability and Governance

This part turns individual practice into sustained capability and clear ownership across the organization. Training gives reviewers repeatable habits that match Parts II–VI; the internal program aligns schedules, tooling, escalation, and risk acceptance, so review depth matches real risk—not heroics.

- [8. Train Security Reviewers](8-train-security-reviewers.md)
- [9. Build an Internal Review Program](9-build-an-internal-review-program.md)

## Conclusion

The conclusion helps you connect the full path: review the code, explain the risk, test the evidence, and build defensible confidence.

- [Build Defensible Confidence](conclusion-from-uncertainty-to-defensible-confidence.md)

## Reference

Use this reference when you want to revisit the secure coding examples behind the chapters.

- [Secure Coding in Practice](secure-coding-in-practice.md)
