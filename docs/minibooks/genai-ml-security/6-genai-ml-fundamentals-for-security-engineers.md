---
title: "6. GenAI / ML fundamentals for security engineers"
keywords:
  - GenAI
  - machine learning
  - training
  - inference
  - fine-tuning
  - RLHF
  - data poisoning
description: >
  ML lifecycle from a security lens: training vs inference, data and fine-tuning risk,
  memorization and leakage, feedback loops, and why evaluation is not security testing.
date: 2026-05-02
---

# 6. GenAI / ML fundamentals for security engineers

## Overview

Effective GenAI security requires a working understanding of how machine learning systems are built, trained, and adapted over time. Security failures often originate before deployment, embedded in data choices, training methods, or feedback mechanisms that shape model behavior long after release.

This chapter provides just enough ML literacy for security professionals to reason about risk without becoming ML engineers. The focus is on security-relevant properties—what changes model behavior, what persists, and where attackers can exert influence.

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. ML risk accumulates across lifecycle stages; inference-only controls are insufficient.
2. Training-time mistakes persist; inference controls cannot reliably undo them.
3. Training data is behavioral source code; data governance is model governance.
4. Fine-tuning, memorization, and feedback loops change risk profiles and create new influence channels.
5. Functional evaluation is not security testing; misuse, leakage, and adversarial stability still matter.

After reading this chapter, we should be able to distinguish training-time from inference-time risk and name where data, fine-tuning, and feedback create lasting influence.

## The ML lifecycle at a glance (security view)

Machine learning systems introduce stages that do not exist in traditional software. The stages below are where security risk accumulates:

1. Data collection and preparation
2. Training or fine-tuning
3. Evaluation and selection
4. Deployment and inference
5. Feedback and continual adaptation

![ML lifecycle (security-oriented view)](assets/material/architecture-ml-lifecycle.png)

Security risk accumulates across stages; controls applied only at inference are insufficient.

## Training vs inference: a critical boundary

Security teams must clearly distinguish training-time and inference-time risks.

- Training time defines long-term behavior.
- Inference time exposes short-term interaction risk.
- Controls applied at inference cannot reliably undo mistakes introduced during training.

Key implications include:

- Poisoned data persists across deployments.
- Memorization cannot be “filtered out” reliably.
- Model updates may reintroduce retired risks.

This boundary is foundational for threat modeling.

## Training data as a security asset

Training data is not configuration—it is behavioral source code.

Security-relevant properties include:

- Data defines model priorities and blind spots.
- Small data changes can have disproportionate effects.
- Labeling errors can encode bias or unsafe behavior.

Common security risks include:

- Data poisoning (malicious or accidental)
- Sensitive data inclusion
- Incomplete or unrepresentative datasets

From a security perspective, data governance is model governance.

## Fine-tuning techniques and their security implications

Fine-tuning adapts a base model to specific tasks or domains. Common approaches include:

- Full fine-tuning: updates most or all model weights.
- Parameter-efficient fine-tuning (PEFT): adapters, LoRA, prefix tuning.
- Instruction tuning: aligning responses to task patterns.

*See also (industry comparison pieces):* “Full fine-tuning, PEFT, prompt engineering, and RAG: which one is right for you?”—same tradeoff space, different risk profiles.

Security implications include:

- Fine-tuning can embed backdoors.
- Adapter layers may bypass base-model safeguards.
- Rollbacks may not remove learned behavior.
- Evaluation gaps amplify risk.

Fine-tuning pipelines must therefore be treated as high-risk build systems.

## Memorization, generalization, and leakage

Models generalize patterns from training data—but generalization is imperfect.

Security-relevant phenomena include:

- Memorization of rare or sensitive records
- Partial reconstruction through inference
- Statistical leakage across many queries

These risks are amplified when:

- Training data contains secrets or PII
- Models are over-parameterized
- Outputs include confidence or reasoning traces

From a security standpoint, privacy failures are often design failures, not bugs.

## Reinforcement learning and feedback loops

Modern GenAI systems frequently incorporate feedback after deployment. Common channels include:

- Human feedback (ratings, corrections)
- Automated feedback (tool outcomes, user behavior)
- Reinforcement learning (explicit or implicit)

![Reinforcement learning from human feedback (illustrative)](assets/image-20251231-161700.png)

*Caption inspiration: RLHF and related alignment / feedback pipelines.*

Security implications include:

- Feedback becomes an input channel.
- Malicious feedback can steer behavior.
- Drift may go unnoticed without baseline controls.
- Guardrails may weaken over time.

Feedback ingestion must be vetted, scoped, and monitored, not assumed benign.

## Evaluation is not security testing

ML evaluation focuses on:

- Accuracy
- Relevance
- Fluency

Security requires additional dimensions:

- Misuse resistance
- Data leakage detection
- Stability under adversarial input
- Consistency across contexts

A model can pass all functional evaluations and still be fundamentally unsafe.

## Key takeaways for security teams

The takeaways below summarize why security must engage before, during, and after model training:

- Training data defines behavior.
- Fine-tuning changes risk profiles.
- Memorization is a persistent threat.
- Feedback loops create new attack surfaces.
- Inference controls cannot fix training failures.

Security must therefore engage before, during, and after model training.
