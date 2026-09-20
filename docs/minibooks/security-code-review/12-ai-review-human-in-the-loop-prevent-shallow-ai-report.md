---
title: Human-in-the-Loop AI Review — Prevent Shallow Reports
keywords:
  - security code review
  - AI-assisted review
  - human in the loop
  - validation
  - shallow findings
  - bug bounty triage
description: How to keep AI-assisted security review evidence-driven—separate leads from validated findings, prove exploitability, and avoid polished but unproven reports.
---

## Chapter 12 - Human-in-the-Loop AI Review: Prevent Shallow Reports

AI can read code quickly, draft payloads, summarize attack surfaces, and run repetitive test steps. That speed is real. It also lets teams produce more vulnerability-looking output than ever before.

The standard that matters has not changed: a finding must be **proven** before it is useful. Output is not evidence. A polished write-up with a severity label and a plausible proof-of-concept does not show that the bug exists in the deployed environment, that it is exploitable, or that the risk is material.

This chapter builds on [Chapter 5 — Use AI to Assist Human Review](5-use-ai-to-assist-human-review.md), [Chapter 6 — Run Fully Automated LLM Review](6-run-fully-automated-llm-review.md), and [Chapter 7 — Control the Risks of AI Review](7-control-the-risks-of-ai-review.md). Those chapters describe how to use AI and where it fails. Here the focus is the **human gate**: how to stop shallow AI output from becoming someone else's triage burden.

## Output Is Not Evidence

AI-assisted tools can generate convincing language faster than humans can validate it. That creates pressure on security teams, engineering leads, and bug bounty programs.

A report should answer basic questions without guesswork:

- What happened?
- How was it reproduced?
- What does the attacker control?
- Which boundary was crossed?
- What impact was **demonstrated**, not only theorized?

Without clear answers, the item may be interesting. It is not ready to drive engineering action. Treat AI output as **input to review**, not as a finished finding—same rule as in Chapter 7: AI can propose; evidence decides.

## The Cost of Shallow AI Reports

Inside a company, shallow AI output has a direct cost: **engineering time**. When security forwards unvalidated model suggestions as findings, product engineers stop feature work to reproduce issues that do not exist, chase dead-end paths, or debate severity on theoretical impact. Each cycle burns hours that could go to real defects or delivery.

The damage is not only hours lost. It **blurs focus**. Engineering and leadership cannot tell which items are urgent, which are noise, and which queue deserves attention. Security teams spend triage time on polish instead of proof. Real issues wait behind a wall of confident but unproven write-ups.

Over time, that pattern **erodes the security team's reputation**. Engineering learns to treat security input as low-signal. Review requests get deprioritized. Fixes get delayed because the last three "critical" items were false alarms. The team that should sharpen risk perception becomes associated with distraction and waste.

Scanner alerts, dependency findings, cloud misconfigurations, and compliance items already fill internal queues. Adding AI-generated speculation on top does not improve security unless the **quality bar** rises with the volume.

Bug bounty programs show the same dynamic at public scale—a useful supporting signal, not a separate problem class. Maintainers and platforms such as Bugcrowd report surges of templated, thinly validated AI submissions that add triage burden instead of signal. What happens externally is a preview of what happens when AI produces many shallow bugs faster than humans can prove them.

The fix is not to reject AI. The fix is to enforce a clear line between **leads** and **validated findings** before engineering time is spent.

## “Looks Vulnerable” Is Not the Same as Vulnerable

One dangerous habit is treating a suspicious pattern as a confirmed flaw. AI makes this worse because it explains *why* something might be bad in fluent prose.

A model may see user input near a query and describe SQL injection. It may see a URL fetch and suggest SSRF. It may see a dangerous API and describe remote code execution. Sometimes it points at a real issue. Often it misses the conditions that decide whether the issue matters.

A reviewer still has to prove **reachability**:

- Does attacker-controlled input reach the dangerous operation?
- Is authentication or authorization required—and enforced elsewhere?
- Is the feature enabled in production?
- Does encoding, normalization, or rejection happen before the sink?
- Does the path cross a trust boundary, or only affect an internal route with no practical impact?

These questions are where real review begins. AI generates hypotheses quickly; hypotheses are not findings. Use model output as a **lead to investigate**, not a conclusion to forward.

Judging that output is its own hard problem—just as in other AI systems. Automated evaluation of **correctness** (is this a real bug?) and **severity** (how bad is it in this deployment?) remains active research. Models can sound confident while missing reachability, misreading patches, or overstating impact. Recent work on LLM vulnerability detection shows that without sufficient code context, precision on real judgments can collapse toward noise; many false positives come from **reasoning errors**, not only from failing to spot a dangerous pattern ([Pearce et al., arXiv:2504.13474](https://arxiv.org/abs/2504.13474)). Hybrid systems that pair static analysis with LLM triage improve recall, but manual follow-up on sampled alerts still finds substantial false discovery—reported upper bounds near half in one ICLR 2025 study ([IRIS](https://proceedings.iclr.cc/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html)). There is no widely trusted auto-grader for “this finding is ready for engineering” yet.

Until that gap closes, teams improve outcomes with process and architecture—not by trusting fluency:

- **Gate promotion on evidence.** Keep the lead → validated-finding bar; require reproduction and demonstrated impact before engineering sees the item.
- **Feed better context.** Supply data-flow paths, call graphs, auth checks, and deployment flags—not isolated snippets—so the model reasons about the same system you will fix.
- **Use hybrid pipelines.** Let deterministic scanners or static analysis propose candidates; use the LLM to summarize, rank, or triage—not as the sole detector ([Chapter 6](6-run-fully-automated-llm-review.md)).
- **Cross-check aggressively.** Second-pass review, multi-agent verification against the repo, or a senior reviewer on high-severity claims catches patch misreads and hallucinated paths.
- **Measure on your code.** Track precision and false-positive rate on merged changes in your stack; tune prompts and rules from labeled outcomes, not from benchmark headlines alone.
- **Calibrate severity to proof.** Tie ratings to reproduced impact and reachability; reject model-generated CVSS when the exploit path is not shown.
- **Close the feedback loop.** Record false positives and accepted findings so the next run learns what “real” means in this codebase.

Research on false-positive mitigation with richer program context (e.g., [LLM4FPM](https://arxiv.org/abs/2411.03079)) shows progress is possible. Production programs still need a human who can say whether the claim survived contact with the running system.

## Why Human Knowledge Still Matters

Tools have always been part of offensive security and code review. Tool output has never been enough.

A scanner may flag a reflected parameter. A static analyzer may flag a dangerous function. A fuzzer may crash a process. A language model may describe a plausible attack path. In every case, someone must understand what the signal means in **this** system.

That understanding comes from repetition: tracing requests, reading code, debugging failures, breaking auth flows, and learning how real deployments fail. It shows up in the questions a reviewer asks, in how a report is written, and in what happens when the first reproduction attempt fails. A practitioner who understands the system adapts. Someone who only trusts the tool's explanation often stalls.

For code review specifically, the methodology from Chapter 3 still applies: name the boundary, trace attacker-controlled input to the sink, and verify the control—or its absence—in code.

## AI Can Speed Good Reviewers and Rusty Ones

Overdependence on AI can make reviewers rusty. This is not an argument against the technology. It is a learning argument.

When a tool answers every question instantly, it is tempting to stop building mental models. When it writes every script, it is tempting to stop practicing. When it explains every error, it is tempting to stop remembering how parsers, frameworks, and identity systems behave.

Offensive security and deep code review reward pattern recognition and technical recall. The hardest issues often connect small details across subsystems. If practitioners stop exercising those skills, they may mistake fluency for competence. Prompting helps; it does not replace judgment.

Use AI to reduce mechanical work so humans spend more time on analysis and validation—not to skip the thinking step.

## Most AI-Assisted Testing Still Uses Familiar Techniques

Much AI security marketing suggests entirely new reasoning. Models do surface patterns across large unfamiliar codebases—that is valuable. In many practical workflows, the underlying moves are still familiar:

- Enumerate endpoints and parameters
- Trace data flow
- Compare authenticated and unauthenticated behavior
- Generate payloads and observe responses
- Check whether application state changed in a security-relevant way

AI often **orchestrates** known techniques at scale: plan, execute, observe, iterate. That is a meaningful improvement. It does not remove the need to interpret results. If the system reports an authorization flaw, someone must know whether the object relationship matters. If it reports SSRF, someone must show access to something the attacker should not reach.

The valuable role for AI is not to replace those decisions. It is to reduce repetitive work around them.

## Leads Versus Validated Findings

Draw a sharp line in your workflow:

| Stage | Definition | AI role |
| --- | --- | --- |
| **Lead** | Something worth investigating—a hypothesis, scanner hit, or model suggestion | Generate, rank, summarize |
| **Validated finding** | Behavior reproduced and tied to demonstrated impact in the target environment | Human proves; AI may assist documentation |

Mixing the two categories creates confusion and wastes engineering time. A healthy program uses AI to produce leads, but **promotion to finding requires evidence**.

For hybrid pipelines (see Chapter 6 and the [AI-era review trends note](../../security-musings/security-code-review-trend-and-practice-in-ai-era.md)), deterministic scanners and gates still own merge authority. LLM comments stay advisory until measured precision on real changes justifies stronger trust.

## Practical Validation Checklist

Before a lead becomes a reported finding, the reviewer should be able to answer:

1. What specific behavior was observed, and where did it occur?
2. What attacker-controlled input, identity, or state was required?
3. What security boundary was crossed—authentication, authorization, tenancy, trust, privilege, or memory safety?
4. What exact steps reproduce the behavior in the **target** environment (not only a local snippet)?
5. What impact was demonstrated, not only the theoretical worst case?
6. What evidence shows the issue is reachable and relevant in the deployed configuration?
7. What would a fix need to change, and how will the team confirm the fix works?

Use this checklist in pull request review, bug bounty triage, and automated LLM pipelines. AI can suggest test ideas and speed reproduction. It should not skip the step where a human verifies the claim against reality.

## The Human Gate Is Still Technical

Human validation is not clerical quality control. It is technical work.

Authorization flaws depend on business logic and object relationships. API issues depend on roles, tenants, and resource graphs. Memory corruption depends on crash context, mitigations, and exploit primitives. Cloud findings depend on identity policies and service-specific behavior. AI can assist with each area; it does not remove the need for someone who knows what they are looking at.

The higher the impact, the more important the human gate. Organizations do not want a confident guess when the result may change engineering priorities, customer trust, or compliance posture. They need proof.

## Avoid Exaggerated Impact

AI-generated reports often overstate severity.

- Reflected input is not cross-site scripting until script execution is shown.
- A URL fetch is not meaningful SSRF until forbidden access is demonstrated.
- A dangerous function is not remote code execution until reachability, control, and execution are proven.

These mistakes erode trust between security and engineering. A CVSS 9.8 rating on a non-issue—or on a bug reachable only by an admin in a disabled feature—is worse than no report.

Experienced reviewers calibrate impact because impact must be earned. A flaw in an admin-only path differs from an unauthenticated internet-facing flaw. A crash may be denial of service, a path to code execution, or an unexploitable reliability issue. The only way to know is to validate.

Good validation prevents both underreporting and overreporting. It avoids crying wolf and builds a strong case when the issue is genuinely serious.

## Use AI Without Losing Skill

The goal is not to avoid AI. The goal is to use it in a way that strengthens review instead of weakening the people doing it.

Security leaders can set expectations:

- **Reward validated impact over volume.** Measure signal quality, not finding count.
- **Train fundamentals before outsourcing.** Junior reviewers should trace data flow and reproduce issues manually—not only prompt a model.
- **Use senior reviewers as force multipliers.** AI accelerates exploration; humans own verdicts.
- **Require explanation.** Can the reviewer reproduce and explain the issue without hiding behind generic language?
- **Use AI as a teaching tool.** When the model suggests an issue, ask why, test the claim, and learn from the result.

Preserve manual practice in request manipulation, code reading, debugging, threat modeling, and impact analysis. Let AI handle summarization, checklist drafts, and first-pass hypothesis generation.

## Key Takeaway

AI will keep improving. Agents will navigate applications, read repositories, and document results faster. Teams should use that progress.

The core standard has not changed—and it is the same standard [Chapter 2 — Think Like a Security Reviewer](2-how-to-think-like-a-security-reviewer.md) established at the start of this book: **reduce uncertainty with evidence**, not with confident language.

When a model suggests SQL injection or SSRF, treat that output like any other unverified claim. Ask what is trusted, what is attacker-controlled, where the trust boundary is, and whether the control is enforced where the attacker cannot remove it. Separate **assumption from evidence**. A polished paragraph is still an assumption until reproduction shows observable behavior.

That is what **prove it** means in practice: prove the bug exists, prove reachability, prove impact, prove the fix works—and leave enough detail that another engineer can follow the same path. AI accelerates the questions; it does not replace the discipline of verifying them.

The best programs will not reject AI. They will run it inside the reviewer mindset—using the machine to explore faster while humans own defensible confidence.

## Close the Book

This book opened with a mindset, not a tool list. [Chapter 2](2-how-to-think-like-a-security-reviewer.md) argued that security review is uncertainty reduction: name trust boundaries, test assumptions, think in threats, and prefer controls the attacker cannot bypass. Everything that followed applied that lens to real work—decomposition and tracing in Part II, code-level patterns in Part III, standards and configuration in Parts IV and V, and AI assistance in Part VI.

Chapter 12 is the closing note on that arc. Faster generation of vulnerability-shaped text does not shorten the path to a finding. It widens the funnel of **leads** and makes the human gate more important, not less. The reviewer who only forwards model output has abandoned the mindset from Chapter 2. The reviewer who validates before engineering spends time has kept it.

If you take one habit from the full book, make it this: **every signal earns its evidence**. Scanner hit, dependency alert, LLM hypothesis, or peer comment—trace it to a boundary, reproduce the behavior, calibrate impact, and document what remains uncertain. That habit scales from a single pull request to an internal program ([Chapters 8–9](8-train-security-reviewers.md)) and to the defensible confidence this series names in the [Conclusion](conclusion-from-uncertainty-to-defensible-confidence.md).

Security code review was never about finding the most issues. It was about understanding what the system allows under hostile conditions—and leaving proof that the team can stand behind. AI belongs in that workflow as a force multiplier. Judgment, validation, and the questions from Chapter 2 still close the loop.

## Reference

- [Chapter 2 — Think Like a Security Reviewer](2-how-to-think-like-a-security-reviewer.md)
- [Chapter 5 — Use AI to Assist Human Review](5-use-ai-to-assist-human-review.md)
- [Chapter 7 — Control the Risks of AI Review](7-control-the-risks-of-ai-review.md)
- [Security Code Review Trends and Practices in the AI Era](../../security-musings/security-code-review-trend-and-practice-in-ai-era.md)
- [OWASP — Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
- Background article (industry discussion of AI validation and shallow reports): [The Hacker News — AI Can Find Bugs, But Human Knowledge Still Proves Them](https://thehackernews.com/2026/07/ai-can-find-bugs-but-human-knowledge.html) (Jul 2026)
- Pearce et al., *Everything You Wanted to Know About LLM-based Vulnerability Detection But Were Afraid to Ask*: [arXiv:2504.13474](https://arxiv.org/abs/2504.13474)
- Li et al., *IRIS* (LLM + static analysis for vulnerability detection): [ICLR 2025](https://proceedings.iclr.cc/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html)
- LLM4FPM (LLM false-positive mitigation with code property graphs): [arXiv:2411.03079](https://arxiv.org/abs/2411.03079)
