---
title: "From mental model to security model"
date: 2026-05-02
keywords:
  - mental model
  - architecture review
  - threat modeling
  - STRIDE
  - security engineering
description: >
  How a security engineer’s work rests on two layers: an architecture model (how the system works)
  and a security model (how it can fail)—and how to move from understanding to adversarial analysis.
---

# From mental model to security model

## Introduction

A **mental model** is a structured way of thinking that enables systematic analysis and informed decision-making. It is especially important in analysis-driven roles. For a security engineer, that mental model is a disciplined approach to **understanding systems** and **evaluating their risks**.

---

## The security mental model

A security engineer’s mental model has two complementary parts:

- **Architecture model** — focuses on how the system is **designed** and **operates**
- **Security model** — focuses on how the system can **fail** or be **compromised**

Together they provide both **clarity** and **critical assessment**.

---

## Architecture model

### Objectives and purpose

The architecture model is the foundation of any security review. Its goal is a **clear, simplified, and accurate** picture of the system: strip unnecessary noise and keep what matters for trust and failure modes.

A complete picture includes:

- System purpose and business motivation
- Core functionality and workflows
- Key components and their responsibilities
- Relationships across components (horizontal and vertical)

### Architectural understanding

To build the architecture model, a security engineer should:

- Gather information about project goals and intended outcomes
- Understand the main logic, functional workflows, and end-to-end data flows
- Identify architectural patterns and system design (for example, distributed systems, pipelines, services)

### Components and relationships

Decompose the system into fundamental building blocks, including:

- **Compute** — services, jobs, runtimes, notebooks
- **Storage** — databases, object storage, data lakes
- **Identity** — IAM roles, users, service principals
- **Networking** — VPCs, subnets, endpoints
- **External integrations** — third-party systems, shared platforms

Key activities:

- Map dependencies between components
- Understand communication patterns (synchronous vs asynchronous)
- Identify trust relationships between services

### Security boundaries

Define and analyze **security boundaries**, such as:

- Network boundaries (for example, VPCs, private vs public zones)
- Account or tenant boundaries
- Identity domains and trust zones

For each boundary:

- Identify what **crosses** the boundary
- Document protocols, APIs, and interfaces
- Record the type and **sensitivity** of data exchanged

### Data flow and process flow

Within and across boundaries, model two flows:

**Data flow**

- How data is created, transformed, stored, and transmitted
- Where sensitive data **resides** and **moves**

**Process / control flow**

- How execution progresses through the system
- Triggers, orchestration, and dependencies

This step ties **behavior** to **data movement** so reviews are not only diagram-deep but risk-relevant.

---

## Security model

### Purpose and mindset

Once the architecture model is in place, the **security model** is built on top of it.

Unlike the architecture model (which emphasizes **understanding**), the security model emphasizes **adversarial** thinking. It evaluates:

- Where the system can be broken
- How trust can be abused
- How components can be repurposed or misused
- What unintended side effects may arise

### Security structure discovery

Systematically analyze the system across two dimensions: **horizontal** and **vertical**.

### Horizontal analysis

Horizontal analysis looks at **interactions between components**:

- Identify communication paths (APIs, protocols, messaging)
- Focus on traffic **across** and **within** security boundaries

Verify:

- What data is exchanged
- How often it is exchanged
- The sensitivity and classification of that data

That discipline keeps **exposure** and **lateral movement** from being hand-waved away.

### Vertical analysis

Vertical analysis decomposes each communication into three layers:

- **Protocol** — how communication occurs
- **Authentication** — who is making the request
- **Authorization** — what actions are permitted

Layered validation helps ensure interactions are **secure**, not only **functional**.

### Threat modeling

Apply structured threat modeling (for example **STRIDE**) to simulate adversarial behavior.

Typical STRIDE categories to walk through:

- Spoofing
- Tampering
- Repudiation
- Information disclosure
- Denial of service
- Elevation of privilege

The objective is to test **robustness**, **resilience**, and **defensive** behavior—not to collect labels for a slide deck.

---

## Conclusion

The security mental model—**architecture model** plus **security model**—is a practical framework for security analysis.

- The **architecture model** deepens understanding by simplifying complexity and surfacing the elements that actually carry risk.
- The **security model** applies adversarial thinking to expose weaknesses and misuse paths.

Together they help a security engineer move past surface-level reactions and deliver a **structured, thorough, and defensible** assessment.
