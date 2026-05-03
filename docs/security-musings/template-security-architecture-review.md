---
title: "Template — Security architecture review document"
description: Reusable outline for application context, risk, architecture, controls, and references in a security architecture review.
date: 2026-05-02
keywords:
  - security architecture review
  - template
  - checklist
  - threat modeling
  - CIA
  - application security
  - risk analysis
---

# Template — Security architecture review document

## Preface: why use a template?

A template is a **living document**: it collects feedback over time and keeps security reviews **consistent** within a given security domain—such as **application security**, **network security**, or **cloud security**.

It carries a **shared mindset** for how to run the work: a common way of thinking, a **dedicated process**, and practices that can **evolve** as threats, stacks, and ownership change.

Treat this document as an **initial base**. **Customize** it for each domain and organization (scope, controls, evidence, and vocabulary) so the review matches how risk is actually owned and decided where you operate.

<p class="explain-muted">Use this as a checklist when preparing or recording a <strong>security architecture review</strong>: it ties business intent to technical design, explicit risks, and control coverage so reviewers and owners share the same picture.</p>

## Section 1 — Application background

- **Team (business owner, risk owner, tech lead, development)** — <span class="explain-muted">Names who can decide scope, accept residual risk, and answer technical questions so the review does not stall on ownership gaps.</span>
- **Application business objectives and impact** — <span class="explain-muted">States what success looks like and what breaks if the app fails, so security priorities align with real business harm, not generic threats.</span>
- **Use cases** — <span class="explain-muted">Describes how actors use the system end-to-end so threat modeling and controls map to actual flows instead of abstract components.</span>
- **Supported use cases** — <span class="explain-muted">Lists what is in production scope today so reviewers know where assurance must be strongest.</span>
- **Out-of-scope use cases** — <span class="explain-muted">Documents what is explicitly excluded so nobody assumes protection where none was designed or funded.</span>
- **Technical requirements mapped to business requirements** — <span class="explain-muted">Shows how each major technical choice backs a business need, making trade-offs and gaps visible under scrutiny.</span>
- **Design principles** — <span class="explain-muted">Captures non-negotiable engineering rules (e.g. least privilege, zero trust boundaries) so later design changes can be checked against intent.</span>

## Section 2 — Risk analysis (business objectives and ecosystem impact)

- **CIA analysis** — <span class="explain-muted">States which of <strong>confidentiality, integrity, and availability</strong> matter most for this system and lists them in <strong>explicit priority order</strong>; that ranking drives trade-offs when controls collide and forms a baseline for <strong>severity adjustment</strong> so risk and incident handling stay aligned with what you protect first.</span>

## Section 3 — Architecture review

- **Architecture diagram** — <span class="explain-muted">Gives a single visual of trust boundaries and data paths so reviewers can reason about blast radius and chokepoints consistently.</span>
- **In-scope components** — <span class="explain-muted">Enumerates what this review covers (services, stores, integrations) so scope creep and orphan systems are avoided.</span>
- **Assumptions (technical and business)** — <span class="explain-muted">Records beliefs the design relies on (latency, identity source, data residency) so wrong assumptions surface before they become incidents.</span>
- **Dependencies** — <span class="explain-muted">Overview of what the application relies on externally so dependency failure or compromise is treated as first-class risk.</span>
- **In-house solution dependencies** — <span class="explain-muted">Internal platforms, shared libraries, and teams the app depends on for security-relevant behavior (auth, logging, deployment).</span>
- **Cloud service dependencies** — <span class="explain-muted">Managed services (IaaS/PaaS/SaaS) and their shared responsibility boundaries so control ownership is clear.</span>
- **External dependencies (supply chain)** — <span class="explain-muted">Third-party software, APIs, and vendors whose compromise or change could affect your system’s integrity or availability.</span>
- **Asset list and data classification** — <span class="explain-muted">Inventory of sensitive data and critical assets so protection and retention match sensitivity and regulatory expectations.</span>
- **Control list mapped to CIA** — <span class="explain-muted">Lists controls and maps each to <strong>confidentiality, integrity, and/or availability</strong> so coverage gaps (e.g. strong integrity but weak availability) are obvious.</span>

## Section 4 — Security controls

- **Cryptography** — <span class="explain-muted">How data is protected in transit and at rest (algorithms, protocols, TLS versions) so reviewers can judge strength and operational feasibility.</span>
- **Key management** — <span class="explain-muted">Where keys live, who can use them, rotation, and break-glass so cryptographic controls remain trustworthy over the key lifecycle.</span>
- **Database security** — <span class="explain-muted">Access model, encryption, backups, and segregation so datastore compromise is constrained and recoverable.</span>
- **Log security** — <span class="explain-muted">What is logged, who can read logs, integrity/tamper protection, and retention so detection and forensics are trustworthy and compliant.</span>
- **Security configuration** — <span class="explain-muted">Hardening baselines, feature flags, and secure-by-default settings so drift from a safe posture is visible and reversible.</span>

## Section 5 — Resources and references

- **Project wiki** — <span class="explain-muted">Canonical link to product/engineering docs so reviewers pull one current source of truth for scope and behavior.</span>
- **Team wiki** — <span class="explain-muted">Runbooks, on-call, and team-specific conventions so operational reality matches what the architecture claims.</span>
- **Document revision history, reviewer, and date** — <span class="explain-muted">Audit trail of who approved which version and when so accountability and “what we knew then” are recoverable after changes.</span>
