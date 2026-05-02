---
title: Framing secure GenAI and ML
keywords:
  - GenAI
  - ML security
  - threat modeling
description: Why GenAI/ML risk is different, how to think threat-model-first, and how controls must adapt.
date: 2025-06-01
---

# Introduction - Framing Secure GenAI and ML

## Purpose and Scope

Generative AI (GenAI) and Machine Learning (ML) systems introduce a **different security model** compared to traditional applications.

Even though they are often built using familiar components—such as APIs, microservices, and cloud platforms—their core behavior is different. Traditional systems follow **fixed logic defined by code**, while GenAI systems rely on **data, probability, and learned patterns**.

This difference changes how we think about security. The way we analyze risks, design controls, and operate systems must also evolve.

This document is a structured set of notes based on training (SANS SEC545: GenAI and LLM Application Security) and additional research. The goal is to answer a few key questions:

* Why do GenAI systems fail?
* Where do the risks come from?
* How should security controls adapt?


## Foundation Comparison

| Area | Traditional AppSec | AI Security |
| --- | --- | --- |
| **Development Model** | Code-driven, deterministic | Data-driven, probabilistic, adaptive |
| **Build-Time Controls** | SCA, SAST, fuzzing | AI supply chain checks, model validation, red teaming |
| **Build-Time Risks** | Vulnerabilities, insecure code, misconfigurations | Poisoned data, rogue models, data leakage |
| **Runtime Controls** | WAF, API security, DAST | Monitoring, guardrails, data integrity checks |
| **Runtime Risks** | DDoS, data breaches, compromised apps | Jailbreaking, information disclosure, resource abuse |


## From Exploit-First to Threat Model–First

A lot of GenAI security content focuses on **specific attacks**—for example, prompt injection or jailbreak techniques. These examples are useful, but they often focus on symptoms rather than root causes.

In these notes, I take a different approach:

* Start with **threat modeling**
  (identify assets, boundaries, and who can influence what)

* Then validate the **attack surface**
  (where inputs can change system behavior)

* Understand **architectural differences**
  (how GenAI systems behave differently from traditional systems)

* Finally, look at **specific attacks** in context

This approach helps reason about **classes of problems**, not just individual issues.


## Why GenAI Security Is Different

Traditional application security is built on a few assumptions:

* Code defines system behavior
* Inputs are treated as data
* Execution flow is predictable
* Failures are repeatable

GenAI systems break these assumptions:

* Prompts can act like **instructions**, not just input
* Data can influence behavior in unexpected ways
* Outputs are generated, not explicitly coded
* The same input may produce different results

Because of this, the key question changes:

Instead of asking *“Where is the bug?”*, we ask:
**“Who can influence the system, through which inputs, and with what impact?”**


## What This Document Covers

This document is organized into three main areas:

### 1. Securing GenAI Applications

Focus on system design:

* Common patterns (e.g., retrieval-based systems, agent-style workflows, fine-tuning)
* How these systems work internally
* Where risks are introduced


### 2. Securing the GenAI Lifecycle

Focus on the full lifecycle:

* Data collection and preparation
* Model training and updates
* Prompt design and feedback loops

These extend the traditional software lifecycle and introduce new risks.


### 3. MLSecOps

Focus on operations:

* How to secure models and ML pipelines in production
* How this builds on, but differs from, DevSecOps


## Guiding Principles

A few principles apply across all sections:

* Treat **models, prompts, and data** as core security elements
* Assume misuse and manipulation—not just coding mistakes
* Keep **human oversight** where decisions matter
* Monitor **behavior and outputs**, not just system logs
* Treat non-deterministic behavior as a **design characteristic**, not a flaw


## Intended Audience

These notes are written for:

* Security architects and application security engineers
* ML and platform engineers
* Cloud and infrastructure security teams
* Governance, risk, and compliance roles

Basic knowledge of application security is helpful. Prior experience with machine learning is not required.
 