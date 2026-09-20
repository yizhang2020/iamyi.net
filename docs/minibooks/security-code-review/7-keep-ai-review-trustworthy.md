---
title: Keep AI Review Trustworthy
keywords:
  - security code review
  - AI-assisted review
  - validation
  - hallucination
  - human in the loop
description: How to keep AI-assisted security review trustworthy—leads versus findings, validation checks, failure modes, and hybrid merge posture.
---

## Chapter 7 - Keep AI Review Trustworthy

### Overview

AI can produce vulnerability-shaped text faster than teams can validate it. The standard has not changed: a finding must be **proven** before it drives engineering work. This chapter is the gate after Chapter 6’s how-to—how we keep fluency from becoming triage burden.

The points below are the ideas this chapter uses again and again.

1. Treat model output as a **lead** until source, sink, reachability, and impact are verified.

2. Promote to a **validated finding** only with reproduction and demonstrated impact in the target environment.

3. Watch failure modes: hallucination, missing context, business-logic blindness, unsafe fixes, prompt injection in repo text, and data exposure.

4. Keep deterministic scanners and CI as the merge floor; keep AI comments advisory.

5. Reward validated signal over volume so reviewers stay sharp.

After reading this chapter, we should be able to run a human gate that accepts only evidence-backed findings from AI-assisted review.

## Leads Versus Validated Findings

Draw a sharp line in the workflow.

A **lead** is something worth investigating—a hypothesis, scanner hit, or model suggestion. AI may generate, rank, and summarize leads.

A **validated finding** is behavior reproduced and tied to demonstrated impact in the target environment. Humans prove it. AI may assist documentation.

Mixing the two wastes engineering time and erodes trust. A healthy program uses AI to produce leads. Promotion to finding requires evidence.

A report ready for engineering should answer: what happened, how it was reproduced, what the attacker controls, which boundary was crossed, and what impact was **demonstrated**—not only theorized.

## Validation Checklist

Before a lead becomes a reported finding, answer:

1. What specific behavior was observed, and where?

2. What attacker-controlled input, identity, or state was required?

3. What security boundary was crossed—authentication, authorization, tenancy, trust, privilege, or memory safety?

4. What exact steps reproduce the behavior in the **target** environment?

5. What impact was demonstrated, not only the theoretical worst case?

6. What evidence shows reachability in the deployed configuration?

7. What must a fix change, and how will the team confirm the fix?

Use the same checklist in pull-request review, bounty triage, and automated LLM comment threads.

## Failure Modes to Watch

**Hallucination and overconfidence.** Models invent missing functions, misread frameworks, and describe unreachable exploit paths. If the claim cannot be tied to code evidence, it is not a finding.

**Missing repository context.** A snippet without routes, middleware, config, or tests yields false positives and false negatives. Retrieve context before strong claims.

**Business-logic blindness.** Syntax is easier than intent. Ownership, enumeration via responses, and illegal state transitions still need human judgment.

**Unsafe fixes.** Regex instead of encoding, denylists instead of allowlists, local cookie flags that miss framework defaults, and home-grown crypto all appear as “fixes.” Require reason, change, abuse-case test, and remaining limits.

**Untrusted repository text.** Comments, PR descriptions, and docs can try to steer the model. Treat repo text as data, not instruction. Separate system instructions from code content.

**Privacy and data exposure.** Rules must cover what may leave the environment, which models are allowed, how logs are stored, and who can see review output. Forbid autonomous agents from approving or deploying their own changes.

## Hybrid Merge Posture

Deterministic tools remain the floor. Known-bad patterns, SAST, secrets, and dependency checks belong in CI with clear merge rules.

AI remains the ceiling for exploration—summaries, hypotheses, triage help, and draft wording—unless measured precision on **our** merges justifies stronger trust.

Humans remain the edge for high-risk change: authentication, authorization, cryptography, deserialization, command execution, uploads, multi-tenant isolation, billing, and public endpoints that handle sensitive data. Even when a model praises a patch, those merges still need human scrutiny.

Do not block merges on raw LLM comments in early rollout. Block on deterministic high-confidence findings. Escalate risky AI leads to a human reviewer.

## Team Habits That Preserve Skill

Overdependence on AI can make reviewers rusty. Set expectations that protect judgment.

Reward validated impact over volume. Measure signal quality, not finding count.

Train fundamentals before outsourcing. Junior reviewers should trace data flow and reproduce issues manually—not only prompt a model.

Use senior reviewers as force multipliers. AI accelerates exploration; humans own verdicts.

Require explanation. Can the reviewer reproduce and explain the issue without hiding behind generic language?

Use AI as a teaching tool. When the model suggests an issue, ask why, test the claim, and learn.

## Key Takeaway

AI proposes. Evidence decides.

Keep leads and findings separate. Validate reachability and impact. Watch the failure modes. Let scanners and CI hold the floor. Let humans keep the edge on high-risk change.

That gate is how Part V stays aligned with Chapter 2: reduce uncertainty with evidence, not with confident language. [Chapter 8](8-enable-developers-to-review-securely.md) turns the habit into developer-led practice.
