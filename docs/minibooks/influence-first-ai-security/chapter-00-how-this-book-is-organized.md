---
title: How this book is organized
keywords:
  - influence-first
  - reading guide
  - book structure
description: >
  Book overview of Influence-First AI Security and a condensed map of parts, chapters,
  and core ideas so readers know how the manuscript is structured.
date: 2026-09-20
---

# How this book is organized

## Overview

Security review still needs system understanding, threat identification, and controls. When AI helps decide what software does, information from many sources can shape those decisions while the system acts with real authority. Traditional methods can miss that relationship if we treat it as incidental. This book makes that relationship a first-class concern.

**Influence-first** means we explicitly ask what can shape an AI-mediated decision, then follow the consequences into connected software, services, and human workflows—and we bound what the system is allowed to do with that decision. The guiding statement is simple: *Trace influence. Bound authority.* “First” means represented and considered consistently. It does not require a fixed starting point, and it does not rank influence above every other risk. Business objectives, risk priorities, and established security principles still guide the review.

This chapter is the map of the condensed book: nine chapters in five parts, plus shared appendices.

The points below are the ideas this chapter uses to orient the rest of the book.

**Core concepts**

1. Influence-first examines how information shapes AI-mediated decisions and how those decisions use authority—inside a whole-system review, not instead of one.
2. The book teaches foundations once, the method once, then applies layers as subsections rather than five parallel domain books.
3. Complete design and incident reviews show the full procedure without re-teaching it.
4. Assurance (test, operate, change) keeps boundaries real after the review.
5. Comparative validation of the method remains proposed research; the study protocol lives in Appendix F.

After reading this chapter, we should be able to state what influence-first means, how the book is structured, and where to read next.

## How to read

Use the path below unless a specific chapter is the immediate need.

1. Finish this chapter for the overview and map.
2. Read Part I (Chapters 1–2) for the proposal and the meaning of influence.
3. Read Part II (Chapters 3–5) for the review procedure.
4. Use Part III (Chapter 6) when applying the method to models, harnesses, extensions, applications, or agents.
5. Study Part IV (Chapters 7–8) for end-to-end design and incident reviews.
6. Finish Part V (Chapter 9) and the [appendices](appendices.md) for assurance and templates.

## Part I — Foundations

Part I states the proposal and defines influence so later chapters do not redefine them.

### Chapter 1 — Influence-First AI Security: Proposal, Foundations, and Limits

**Core ideas:** what the book claims; what “first” means; security foundations we keep; evidence versus untested comparative benefit; preview of the four layers.

**Read:** [Chapter 1](chapter-01-influence-first-security.md) · evaluation protocol → [Appendix F](appendices.md)

### Chapter 2 — Understanding Influence: From Information to Consequence

**Core ideas:** exposure → behavioral influence → security consequence; legitimate versus unauthorized influence; paths through training, skills, retrieval, memory, tools, delegation, and feedback; a complete candidate finding.

**Read:** [Chapter 2](chapter-02-understanding-influence.md)

## Part II — The Method

Part II turns architecture into findings, controls, and evidence. Teach the procedure here once.

### Chapter 3 — Define the System, the Task, and the Authority

**Core ideas:** assets and unacceptable outcomes; human authorization versus configured permissions; inventory; authority map for facts, approvals, and policy.

**Read:** [Chapter 3](chapter-03-system-task-authority.md)

### Chapter 4 — Map Influence Across Decisions and Boundaries

**Core ideas:** decision points and source roles; forward and backward tracing; transformations, persistence, feedback, and alternate routes; candidate path versus demonstrated failure.

**Read:** [Chapter 4](chapter-04-mapping-influence.md)

### Chapter 5 — Identify Threats, Design Controls, and Define Evidence

**Core ideas:** STRIDE plus influence questions; actionable findings; enforcement points; guidance is not enforced policy; tests, owners, and residual risk.

**Read:** [Chapter 5](chapter-05-threats-controls-and-evidence.md)

## Part III — Apply Across Layers

Part III does not re-teach the method. It states only what changes at each layer.

### Chapter 6 — Apply the Method Across AI System Layers

**Core ideas:** same questions everywhere; deltas by layer—models, harnesses, skills/tools/MCP, AI applications, agent systems—plus a short layer checklist.

| Subsection | Core ideas |
| --- | --- |
| **6.1 Models** | Training, fine-tuning, provenance; evaluation limits; downstream enforcement when behavior is uncertain |
| **6.2 Harnesses** | Context assembly, planning/retries, tool routing, memory, sandbox, interruption |
| **6.3 Skills, tools, and MCP** | Extension as software; instruction versus executable routes; credentials; supply chain; revocation |
| **6.4 AI applications** | Business meaning (requested / recommended / verified / approved); RAG source roles; structured output; transactions |
| **6.5 Agent systems** | Roles by authority; peer messages as claims; delegation; shared channels; containment |

**Read:** [Chapter 6](chapter-06-apply-across-layers.md)

## Part IV — Complete Reviews

Part IV applies the full procedure without gaps between diagrams, findings, and controls.

### Chapter 7 — Complete Design Review: Customer-Service Agent

**Core ideas:** one system from task through architecture, authority, influence map, findings, controls, tests, and residual risk.

**Read:** [Chapter 7](chapter-07-complete-design-review.md)

### Chapter 8 — Complete Incident Review: The Agent as an Attacker

**Core ideas:** reconstruct impact forward and backward; separate permissions, misuse, and exploitation; interruption points; what the incident supports—and does not—about influence-first.

**Read:** [Chapter 8](chapter-08-agent-intrusion-case-study.md)

## Part V — Assurance

Part V keeps boundaries working after the design review.

### Chapter 9 — Assure Continuously: Test, Operate, and Manage Change

**Core ideas:** tests from findings (including legitimate work); observe, contain, and recover trustworthy state; change triggers, versioning, ownership, and release gates.

| Section | Core ideas |
| --- | --- |
| **9.1 Test** | Cases from findings; exposure versus execution versus impact; what results can and cannot prove |
| **9.2 Operate** | Observe sources and effects; contain; revoke; recover including memory |
| **9.3 Manage change** | Re-review triggers; version assumptions and evidence; ownership across providers |

**Read:** [Chapter 9](chapter-09-assure-continuously.md)

## Shared appendices

| Appendix | Contents |
| --- | --- |
| **A** | Review templates (system, authority, influence, threat) |
| **B** | Control and validation templates |
| **C** | Terminology and notation |
| **D** | Framework cross-references |
| **E** | Case-study evidence guide |
| **F** | Research and evaluation protocol (comparative study design) |

**Read:** [Shared appendices](appendices.md)

## Condensed map (quick reference)

| Part | Chapters | Role |
| --- | --- | --- |
| I Foundations | 1–2 | Proposal, foundations we keep, meaning of influence |
| II Method | 3–5 | System/authority → map → threats/controls/evidence |
| III Layers | 6 | Domain deltas as subsections |
| IV Reviews | 7–8 | Design review and incident review |
| V Assurance | 9 | Test, operate, manage change |
| Appendices | A–F | Templates and evaluation protocol |

Next: [Chapter 1 — Influence-First AI Security: Proposal, Foundations, and Limits](chapter-01-influence-first-security.md).
