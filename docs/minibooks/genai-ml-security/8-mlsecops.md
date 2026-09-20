---
title: "8. MLSecOps"
keywords:
  - MLSecOps
  - DevSecOps
  - MLOps
  - evaluation gates
  - model governance
description: >
  How MLSecOps extends DevSecOps for ML and GenAI: artifacts, pipelines, gates, monitoring,
  and feedback loops—with controls for non-determinism and behavioral drift.
date: 2026-05-02
---

# 8. MLSecOps

## Overview

DevSecOps provides a strong foundation for securing software delivery, but ML systems introduce new artifacts, feedback loops, and failure modes that DevSecOps alone does not address. MLSecOps extends DevSecOps to ensure models, data, prompts, and evaluations are governed with the same rigor as code—while accounting for non-determinism and behavioral drift.

This chapter explains how MLSecOps builds on DevSecOps, where it diverges, and which controls are required to operate GenAI systems safely at scale. It complements the lifecycle framing in [chapter 7](7-securing-the-genai-application-lifecycle.md).

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. DevSecOps remains essential; MLSecOps adds what must be secured when behavior can change without code changes.
2. First-class artifacts include datasets, labels, models/adapters, prompts/policies, and evaluations.
3. Unique threats include training poisoning, model substitution, unsafe deserialization, evaluation bypass, and feedback poisoning.
4. Evaluation gates and runtime monitoring must cover robustness, misuse, leakage, and behavioral signals—not only uptime.
5. Feedback loops are a security boundary and need vetting, scope limits, and approvals for re-training.

After reading this chapter, we should be able to contrast DevSecOps with MLSecOps and name the pipeline stages, gates, and monitoring signals that GenAI operations require.

## DevSecOps as the foundation

DevSecOps practices remain essential and do not go away with GenAI. Core practices include:

- CI/CD pipelines and artifact promotion
- Secrets management and IAM
- Infrastructure as Code (IaC)
- Logging, monitoring, and incident response

What changes is what must be secured, and how assurance is established.

## DevSecOps vs MLSecOps (comparison)

The table below contrasts traditional DevSecOps with MLSecOps for GenAI and ML:

| Dimension | DevSecOps (traditional) | MLSecOps (GenAI / ML) |
| --- | --- | --- |
| Primary artifacts | Code, containers | Models, prompts, datasets, evals |
| Change triggers | Code commits | Data updates, fine-tunes, feedback |
| Determinism | Deterministic builds | Probabilistic behavior |
| Testing focus | Functional & security tests | Robustness, misuse, drift |
| Rollback | Revert code | Behavior may persist |
| Monitoring | Errors, latency | Behavioral & semantic signals |
| Supply chain | Dependencies & images | Models, data sources, adapters |

Key takeaway: MLSecOps adds controls where behavior changes without code changes.

## MLSecOps pipeline (end-to-end)

MLSecOps pipelines introduce additional stages beyond CI/CD. End-to-end stages typically include:

1. Data ingestion & validation
2. Training / fine-tuning jobs
3. Evaluation & gating
4. Model registry & signing
5. Deployment & serving
6. Runtime monitoring
7. Feedback ingestion & re-training

![MLSecOps / LLM security pipeline (illustrative)](assets/image-20251231-173833.png)

*Caption inspiration: “MLSecOps: secure your large language model (LLM) applications.”*

## Artifact governance in MLSecOps

MLSecOps treats the following as first-class security artifacts:

| Artifact | Why it matters |
| --- | --- |
| Datasets | Define long-term behavior |
| Labels | Encode policy and bias |
| Models / adapters | Executable decision logic |
| Prompts / policies | Control plane |
| Evaluations | Gate behavior changes |

### Controls to apply

Controls for these artifacts typically include:

- Provenance tracking
- Versioning and immutability
- Signing and verification
- Least-privilege access

## Threats unique to MLSecOps

The threat categories below persist even when traditional CI/CD is secure:

| Threat category | Description |
| --- | --- |
| Training poisoning | Malicious or tainted data alters behavior |
| Model substitution | Swapping approved models with unsafe ones |
| Unsafe deserialization | Executing malicious model artifacts |
| Evaluation bypass | Shipping models without safety gates |
| Feedback poisoning | Steering behavior post-deployment |

These threats persist even when traditional CI/CD is secure.

## Evaluation gates (security, not accuracy)

In MLSecOps, evaluation gates replace binary “build passes.” Gate types commonly include:

| Evaluation type | Purpose |
| --- | --- |
| Robustness tests | Stability under adversarial input |
| Misuse scenarios | Resistance to prompt manipulation |
| Leakage checks | Memorization & inference risks |
| Drift baselines | Detect behavioral change |

![Evaluation of LLM-based applications (illustrative)](assets/image-20260101-143847.png)

*Caption inspiration: “Steady the course: navigating the evaluation of LLM-based applications.”*

## Runtime monitoring: from metrics to meaning

Traditional monitoring answers: *Is the service up?*  
MLSecOps monitoring must answer: *Is the model behaving safely?*

Useful monitoring signals include:

| Monitoring signal | What it detects |
| --- | --- |
| Prompt / context patterns | Injection attempts |
| Tool invocation rates | Privilege abuse |
| Output semantics | Policy drift |
| Retrieval sources | RAG poisoning |

Principle: monitor behavior and intent, not just availability.

## Feedback loops as a security boundary

Feedback is powerful—and dangerous. Risk by feedback type includes:

| Feedback type | Risk |
| --- | --- |
| Human ratings | Social engineering |
| Automated signals | Reinforcing unsafe shortcuts |
| Self-training | Compounding drift |

The following illustrates an architectural option that isolates the feedback loop from the rest of the machine learning pipeline:

![Strategic feedback loops in ML systems (illustrative)](assets/image-20260101-145452.png)

*Caption inspiration: “Elevating machine learning systems through strategic feedback loops.”*

### Controls

Controls for feedback channels include:

- Vet feedback sources
- Scope what feedback can change
- Require approvals for re-training

## Operating principles for MLSecOps

Operating principles that carry across the pipeline include:

- Assume drift; detect it continuously
- Gate behavior, not just artifacts
- Separate authority from language
- Keep humans in critical loops
- Design for rollback that includes behavior
