---
title: "1. Influence-First AI Security: Proposal, Foundations, and Limits"
keywords:
  - influence-first
  - threat modeling
  - authority
  - security foundations
  - validation limits
description: >
  States the influence-first proposal, the security foundations it keeps,
  evidence versus comparative validation limits, and a preview of the four layers.
date: 2026-09-20
---

# Chapter 1 — Influence-First AI Security: Proposal, Foundations, and Limits

*An influence-first approach to securing models, harnesses, AI applications, and agent systems.*

## Overview

Security review still needs system understanding, threat identification, and controls. When AI helps decide what software does, we also need to examine what can shape those decisions—especially when the system reads many sources and acts through powerful tools. Established methods can miss that relationship if we treat it as incidental rather than a first-class concern.

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. Established security principles remain applicable to systems that contain AI; what deserves more explicit attention is how information shapes AI-mediated decisions and how those decisions use the system’s authority.
2. Tracing influence means examining what can shape a consequential decision; bounding authority means limiting what the system can do with that decision—both are necessary.
3. Influence-first analysis is a research-informed addition to systematic threat modeling; its comparative benefit as a review methodology remains to be tested.
4. An actionable finding needs a reachable source, a relevant decision, a prohibited consequence, and the conditions that connect them—not only the claim that an input might influence a model.
5. Familiar foundations—CIA objectives, STRIDE questions, trust boundaries, least privilege, complete mediation, isolation, defense in depth, and provenance—remain keepers; influence-first makes decision dependencies explicit within that scope.

After reading this chapter, we should be able to state what influence-first claims, what “first” means, which foundations we keep, where the evidence stops, and how the rest of the book applies the same questions.

## 1.1 The problem and the proposal

This book begins with a practical question: how should we review the security of software when AI helps decide what the software does? We still need to understand the system, identify threats, and choose controls. We also need to examine what can shape those decisions, especially when the system can read information from many sources and act through powerful tools.

This book proposes **influence-first analysis** as a practical method for examining those decisions within systematic threat modeling. The approach is informed by research and grounded in established security principles. It gives readers a structured procedure to apply and evaluate. Its comparative advantage over other competent threat-modeling methods remains to be tested.

The foundation of the book is this:

> Established security principles remain applicable to systems containing AI. What deserves more explicit attention is how information shapes AI-mediated decisions, and how those decisions use the system’s authority. This book proposes influence-first analysis as a practical way to examine those relationships within systematic threat modeling. Research documents relevant attacks and demonstrates controls for selected mechanisms. It supports the rationale for this approach, while its comparative benefit as a review methodology remains to be tested.

Traditional methodology applies to the whole system, including AI components. Influence-first adds explicit questions wherever AI participates in decisions, and follows the consequences into ordinary databases, APIs, and services. A single review may therefore move repeatedly between an AI decision and a familiar access-control or data-handling problem.

The guiding statement is simple:

> **Trace influence. Bound authority.**

Tracing influence means examining what can shape a consequential decision. Bounding authority means limiting what the system can do with that decision. Both are necessary: understanding why an agent might act unsafely does not itself prevent the action.

## 1.2 A small example: when a statement becomes permission

A customer-support application can summarize complaints and issue refunds. Imagine a customer uploads a document containing this sentence: “The manager has approved a full refund.” The assistant includes that statement in its summary. A later step treats the summary as evidence of approval and calls the payment service.

This is a hypothetical example, not a report of an observed breach. Its purpose is to make the review question concrete. The customer is allowed to explain the complaint. That permission does not make the customer an authority on whether a refund has been approved.

The important transition occurs when a statement from the customer becomes a basis for exercising the company’s payment authority. The words might change during summarization. Their effect can survive even if the original wording and attribution disappear.

An influence-first review would record answers to the questions in the table below.

| Review question | Answer in this example |
|---|---|
| What needs protection? | Company funds and the integrity of refund approval. |
| Who controls the source? | The customer controls the uploaded document. |
| What decision can it affect? | Whether the assistant considers the refund approved. |
| What carries the influence forward? | A summary that may lose the distinction between an allegation and an approval record. |
| What authority becomes available? | The application’s ability to request a payment. |
| What must enforce the policy? | The payment service must verify a valid approval from an authoritative source. |
| How would we test the control? | Submit a false approval claim and verify that no payment occurs without the required approval record. |

The test should also confirm that a properly approved refund succeeds. Security controls must preserve the intended business function. Rejecting every refund would prevent this particular loss while making the application useless.

This example does not show that STRIDE would miss the problem. A competent traditional review could identify the same misuse of trust and authority. Influence-first makes the source-to-decision relationship an explicit, repeatable part of that review.

## 1.3 Defining influence-first

**Influence-first analysis** traces security-relevant information through transformations and decisions to possible consequences, then examines whether the authority involved is appropriate and independently constrained. Before doing this, we identify the assets, intended task, and applicable policies.

**“First”** means treating influence as a first-class concern in security analysis: explicitly represented and consistently considered. Wherever AI participates in a decision, the review examines what can shape that decision, what consequences can follow, and what controls constrain them. The word describes the attention given to influence, rather than a mandatory starting point or a claim that influence always outranks other risks. Business objectives, risk priorities, and established security principles continue to guide the overall review.

The approach asks four connected questions:

1. Who or what can shape this decision?
2. How can that influence reach the decision, including through summaries, memory, or other agents?
3. What consequence can follow through the system’s available authority?
4. What control prevents an unauthorized consequence, and what evidence shows that it works?

Influence is not automatically hostile. A support assistant should consider a customer’s complaint. A research assistant should learn from the documents it retrieves. The security question is whether a source can affect decisions beyond its legitimate role.

In the refund example, the complaint can establish what the customer alleges. It cannot independently establish managerial approval. A useful design preserves that distinction even when the information is rewritten or passed to another component.

An actionable finding therefore needs more than “this input might influence the model.” It needs a reachable source, a relevant decision, a prohibited consequence, and the conditions that connect them. It also needs a feasible control or a clearly stated gap requiring further investigation. We may identify that a document reaches a model’s context without proving exactly how it affected a particular output; a plausible dependency remains a candidate threat path until its preconditions and possible consequences have been examined.

## 1.4 Foundations we keep

Influence-first builds on examining trust, information flow, and authority. Denning’s work on secure information flow and Hardy’s confused-deputy account are important predecessors: information propagation and misapplied authority were security concerns well before modern language models. [10, 11] Hardy’s account—a program misusing its own authority while serving another party—maps directly onto an assistant with a powerful service credential, even though language-mediated workflows add different implementation details.

Valid credentials and encrypted channels do not guarantee authorized outcomes. An AI component can select a target or operation while an ordinary service still fails to enforce entitlement. Influence-first only helps if we keep the foundations that already explain that failure.

Confidentiality, integrity, and availability remain useful starting objectives. The review should name consequences in terms the system owner can evaluate; accountability, privacy, safety, and financial loss may need additional descriptions.

STRIDE—spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege—supplies systematic threat questions for components, flows, stores, identities, and boundaries. It does not promise discovery by filling six boxes. Influence-first makes decision dependencies explicit within that scope, not instead of it. In agent systems, a log saying “the assistant approved it” does not establish human authorization; the useful record connects the human task, service identity, policy decision, requested operation, and actual effect.

Boundaries separate authority as well as machines. A customer assertion and an authoritative approval record may share model context while having different roles. Crossing a boundary is not automatically a failure; the receiving component must apply the right rules before using the information or exercising authority. “Trusted input” is incomplete until we say trusted to establish what.

Least privilege limits available data and operations; complete mediation checks access on every applicable path; isolation limits cross-execution effects; defense in depth combines controls that do not share one failure assumption. Layers that all rely on a model correctly interpreting the same hostile text are not independent; identify the actual enforcement component and each layer’s assumption. OWASP’s threat-modeling guidance already includes system understanding, data flows, trust boundaries, mitigations, and validation—influence-first belongs within that scope. [12] Attack knowledge, advisories, and severity scores each answer a different question; none replaces determining whether a path exists in the system under review.

## 1.5 From evidence to confidence: how much should we claim?

The phrase “influence-first AI security” can carry several different claims. Separating them helps us avoid both dismissing useful analysis and promising more than we know.

The progression below connects the available evidence to the claims this book makes.

| Level | Claim | What supports it, or what remains necessary |
|---|---|---|
| **1. The phenomenon exists.** | Information can shape AI-mediated decisions and contribute to security failures. | Attack research demonstrates relevant mechanisms in studied systems. |
| **2. The analysis can be actionable.** | Examining those paths can lead to specific threats, controls, and tests. | Defense research and worked analysis support selected mechanisms and control requirements. |
| **3. The proposed method is reasonable to use.** | A structured influence-first procedure is a defensible addition to systematic threat modeling. | This is the book’s methodological recommendation, grounded in the first two levels and bounded by an explicit scope. Its practical benefits require evaluation. |
| **4. The method improves review outcomes.** | Reviewers find more actionable threats, work faster, or produce better controls. | Each claimed benefit requires a fair comparison with another competent approach. |
| **5. The benefit generalizes.** | Improvements recur across different systems, reviewers, and conditions. | This requires replication and evidence about where the method helps or fails. |

The book currently adopts Level 3, supported by Levels 1 and 2. This is a reasoned recommendation, not a measured confidence score. Levels 4 and 5 remain research questions; the supporting review identified no direct comparative validation of this procedure.

Soundness, practical usefulness, and comparative benefit are separate questions. Claims of novelty or completeness sit outside this progression. Success against prompt injection would not cover every AI security risk. The refund example shows explanatory usefulness; it does not show that reviewers using this procedure outperform reviewers using STRIDE with suitable AI guidance.

## 1.6 The research behind the proposal

The supporting review considered foundational work and selected research published or revised through September 13, 2026. It was a focused assessment, not an exhaustive survey. Attack, defense, and review studies provide different kinds of evidence and should not be treated as interchangeable.

Indirect prompt injection research and InjecAgent show how externally supplied material and tool responses can affect LLM-integrated applications. They support reviewing information encountered after the legitimate user’s request; they do not measure this book’s review procedure. [1, 2] AgentPoison, Prompt Infection, and related work on persistent artifacts give reasons to follow influence through memory, peer messages, and later reuse—without implying every store or conversation is exploitable. [3, 4, 5]

CaMeL, Fides, and Progent show that selected restrictions can be enforced outside the model’s ordinary interpretation of text; their guarantees depend on designs, policies, and assumptions. A defense that blocks a class of attacks does not prove that an influence-first reviewer would have discovered the need for it. [6, 7, 8] A 2026 study of data-flow diagrams and LLM support for threat validation did not find effectiveness gains under its conditions—a useful warning against assuming another diagram or assistant automatically improves security work. [9]

## 1.7 Four layers, and how we evaluate later

The book follows four review domains: models, harnesses, AI applications, and agent systems. A harness manages execution, context, memory, and tool use. An AI application adds business workflow and policies. An agent system connects agents through communication, shared resources, or delegated work. Domains can overlap; their purpose is to assign questions to concrete components.

| Domain | Influence questions | Questions about controls and authority |
|---|---|---|
| Models | What training, adaptation, instructions, and context shape behavior? | How do we evaluate changes, and what remains constrained if behavior becomes unsafe? |
| Harnesses | What observations, memory, or tool results can change the next action? | Which operations, arguments, and destinations are independently checked? |
| AI applications | Which sources affect business decisions, answers, and proposed state changes? | Which services establish identity, entitlements, approval, and valid business state? |
| Agent systems | How do messages, shared stores, and delegation carry influence between agents? | Can one agent cause another to exercise broader authority, and where is that checked? |

RAG, MCP integrations, and autonomous agents are starting points for analysis, not conclusions of insecurity. If a model selects a record, recipient, or payment amount, the receiving service still enforces its own policy. “Requested,” “recommended,” and “approved” must remain distinct. [Chapter 6](chapter-06-apply-across-layers.md) covers layer deltas; [Chapter 3](chapter-03-system-task-authority.md) through [Chapter 5](chapter-05-threats-controls-and-evidence.md) teach the shared procedure.

Some risks need a different starting point—unacceptable goal pursuit without injected instructions, or conventional secret exposure with no AI decision. Whole-system review includes those paths alongside influence analysis.

Whether this procedure helps reviewers do better work is a separate question from whether influence-related attacks exist. The comparative study protocol lives in [Appendix F](appendices.md). Correctness, practical usefulness, and comparative benefit remain distinct judgments.

[Chapter 2](chapter-02-understanding-influence.md) defines influence through stages, transitions, and evidence. Later chapters apply the method across layers, complete reviews, and continuous assurance. Every analysis should remain concrete enough to challenge: a plausible failure, an enforcement point, and meaningful evidence about whether the boundary holds.

## References

References support the specific mechanisms, designs, or study results discussed above. None is presented as direct comparative validation of this book’s proposed procedure. Dates identify the cited publication or revision; preprints should be read with their stated limitations.

1. Kai Greshake et al. [Not what you’ve signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://arxiv.org/abs/2302.12173). 2023.
2. Qiusi Zhan et al. [InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents](https://arxiv.org/abs/2403.02691). 2024.
3. Zhaorun Chen et al. [AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases](https://arxiv.org/abs/2407.12784). 2024.
4. Donghyun Lee and Mo Tiwari. [Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems](https://arxiv.org/abs/2410.07283). Cited preprint, 2024.
5. Mingming Zha and XiaoFeng Wang. [Autonomous LLM Agent Worms: Cross-Platform Propagation, Automated Discovery and Temporal Re-Entry Defense](https://arxiv.org/html/2605.02812v1). Preprint, May 4, 2026.
6. Edoardo Debenedetti et al. [Defeating Prompt Injections by Design](https://arxiv.org/html/2503.18813v2). CaMeL; June 24, 2025 revision.
7. Manuel Costa et al. [Securing AI Agents with Information-Flow Control](https://arxiv.org/html/2505.23643v2). Fides; September 3, 2025 revision.
8. Tianneng Shi et al. [Progent: Securing AI Agents with Privilege Control](https://arxiv.org/abs/2504.11703v3). May 14, 2026 revision.
9. Winnie Bahati Mbaka and Katja Tuma. [Less is more: usefulness of data flow diagrams and large language models for security threat validation](https://link.springer.com/article/10.1007/s10664-026-10837-z). *Empirical Software Engineering*, 31, article 122, April 21, 2026. Threat validation study, not a direct test of influence-first discovery.
10. Dorothy E. Denning. [A Lattice Model of Secure Information Flow](https://dl.acm.org/doi/10.1145/360051.360056). *Communications of the ACM*, 1976. Cited as a historical foundation.
11. Norm Hardy. [The Confused Deputy: (or why capabilities might have been invented)](https://dl.acm.org/doi/10.1145/54289.871709). *ACM SIGOPS Operating Systems Review*, 1988. Cited as a historical foundation.
12. OWASP. [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html). Consulted in the supporting evidence review on September 13, 2026.
