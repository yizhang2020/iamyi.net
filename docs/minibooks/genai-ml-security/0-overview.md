---
title: Overview
keywords:
  - GenAI
  - overview
  - risk
  - MLSecOps
  - governance
description: >
  Short overview for leaders: why GenAI risk differs, key risk areas, how we approach security,
  and the leadership takeaway on influence and accountability.
date: 2026-05-02
---

# Overview

GenAI systems introduce new security risks that bypass traditional controls. These risks do not come from broken infrastructure, but from uncontrolled influence over AI behavior.

Even well-secured environments can produce:

- Data leakage
- Unauthorized actions
- Silent behavior drift
- Compliance violations

**Core concepts**

The points below are the ideas this minibook uses again and again. Read them once here; the later chapters develop each one.

1. AI behavior is probabilistic, not deterministic.
2. Data and prompts influence decisions directly.
3. Models evolve after deployment.
4. Security failures may not be repeatable.
5. AI security is about controlling influence and accountability—not about blocking inputs alone.

After reading this overview, we should be able to name why GenAI risk differs from traditional AppSec, where the main risk areas sit, and how this minibook approaches controls.

## What is different from traditional applications

GenAI differs from traditional applications in how behavior is produced and how failures show up:

- AI behavior is probabilistic, not deterministic.
- Data and prompts influence decisions directly.
- Models evolve after deployment.
- Security failures may not be repeatable.

*(See the full minibook, starting with [chapter 1](1-framing-secure-genai-and-ml.md) and [chapter 3](3-genai-vs-traditional-applications.md).)*

## Key risk areas

These are the places where influence over GenAI behavior commonly goes wrong:

- Prompt and context manipulation
- Retrieval of untrusted or sensitive data
- AI-driven tool execution
- Training and feedback loop poisoning
- Undetected behavioral drift

## Our security approach

The control posture in this minibook follows those risks:

- Threat-model-first architecture reviews ([chapter 7](7-securing-the-genai-application-lifecycle.md))
- Clear control of who can influence AI behavior
- MLSecOps governance for models and data ([chapter 8](8-mlsecops.md))
- Continuous monitoring of AI behavior, not just uptime
- Human approval for high-risk AI actions

Organizations that treat AI like traditional software will lose control over time. AI security is not about blocking inputs—it is about controlling influence and accountability.

For the full argument and principles, see [chapter 9 — conclusion](9-conclusion-principles-and-the-road-ahead.md).
