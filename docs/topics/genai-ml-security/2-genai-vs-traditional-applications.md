---
title: "2. GenAI vs traditional applications"
keywords:
  - GenAI
  - AppSec
  - trust boundaries
  - non-determinism
  - control plane
description: >
  Why traditional AppSec assumptions break for GenAI: control shifts from code to language and
  data, trust boundaries move, and failures become probabilistic and semantic.
date: 2026-05-02
---

# 2. GenAI vs traditional applications

## Purpose of this chapter

Security failures in GenAI systems often occur when **traditional application security assumptions** are applied without adjustment. This chapter explains why those assumptions break, and how GenAI systems introduce fundamentally different trust, control, and failure models.

The goal is not to replace AppSec principles, but to **reframe** them so they remain effective in environments where behavior is probabilistic, data-driven, and adaptive.

## Traditional application security assumptions

Most established security practices are built on several implicit assumptions:

- **Code defines behavior:** control flow is explicit, testable, and versioned.
- **Inputs are passive data:** user input influences state, not execution logic.
- **Execution is deterministic:** the same input produces the same output.
- **Failures are repeatable:** bugs can be reproduced, debugged, and patched.

These assumptions underpin secure coding standards, testing strategies, and runtime controls.

## Why these assumptions fail in GenAI systems

GenAI systems invert or weaken each of these assumptions:

- Behavior emerges from **inference**, not code paths.
- Inputs shape **reasoning**, not just state.
- Outputs are **probabilistic**, even with identical inputs.
- Failures may be **non-repeatable**, context-dependent, and **semantic**.

As a result, many security controls that work well for traditional applications become **incomplete or misleading** when applied to GenAI systems.

## Control plane shift: from code to language

In traditional systems, the control plane is implemented in **code**: conditionals, authorization checks, and execution paths. In GenAI systems, **natural language** becomes part of the control plane.

- Prompts define goals and constraints.
- Retrieved data can override intent.
- Instructions compete for priority.
- **Ambiguity becomes exploitable.**

This shift means that security-relevant decisions may occur **inside the model**, outside the visibility of standard enforcement mechanisms.

## Data as executable influence

In GenAI systems, data is no longer passive:

- Retrieved documents influence reasoning.
- Training data shapes long-term behavior.
- Feedback loops modify future outputs.
- Memory persists across interactions.

Unlike SQL injection or XSS, these influences are **semantic** rather than syntactic. The system may behave “as designed” while still violating security intent.

This leads to a critical distinction:

> GenAI attacks often manipulate **meaning**, not execution.

## Trust boundary reinterpretation

Traditional trust boundaries are enforced through interfaces, authentication, and authorization. In GenAI systems, new **implicit** trust boundaries appear:

- Between prompt segments
- Between retrieved data and system instructions
- Between model reasoning and tool execution
- Between past interactions and the current context

These boundaries are often **undocumented**, **unenforced**, or assumed safe.

![Trust and control flow (illustrative)](../assets/image-20251230-030753.png)

*Placeholder figure — add a more detailed caption or replace when a final diagram is available.*

**Diagram references (conceptual):**

- Inspired by [OpenAI function calling](https://platform.openai.com/docs/guides/function-calling) concepts
- Inspired by [agentic AI design patterns](https://learn.microsoft.com/azure/architecture/ai-ml/guide/ai-agent-design-patterns) (Microsoft Azure Architecture Center)

## Determinism vs non-determinism as a security property

Non-determinism is not merely an engineering challenge—it is a **security property**.

Implications include:

- Regression testing cannot rely on exact output matches.
- “Fixing” a prompt may introduce new failure modes.
- Attack success may vary across attempts.
- Monitoring must detect **behavioral drift**, not just errors.

Security teams must shift from binary pass/fail thinking to **probabilistic risk management**.

## Comparison summary

| Dimension | Traditional application | GenAI application |
| --- | --- | --- |
| Control plane | Code | Language + data |
| Input role | Passive | Behavioral influence |
| Execution | Deterministic | Probabilistic |
| Failure mode | Reproducible bugs | Contextual misuse |
| Security focus | Vulnerabilities | Influence paths |

## Security implications

This comparison leads to several practical conclusions:

- **Input validation alone is insufficient.**
- **Authorization** must extend to actions inferred by models.
- **Logging** must capture context and reasoning signals.
- **Threat modeling** must include semantic attack paths.

Most importantly, security must reason about **intent**, not just execution.
