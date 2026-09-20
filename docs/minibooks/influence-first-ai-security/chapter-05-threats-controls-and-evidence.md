# Chapter 5 — Identify Threats, Design Controls, and Define Evidence

*Trace influence. Bound authority.*

## Overview

Many attack stories can describe the same missing check, and a model instruction that refuses an unsafe request is not the same as an enforcement point that blocks the effect. Useful review work separates scenario, weakness, and consequence; groups variants by control requirement; places policy where authority is exercised; and ships with evidence—including tests of alternative routes and legitimate work.

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. A scenario describes how something could happen; a weakness describes the failed requirement; a consequence describes the loss or policy violation—and risk follows impact, exposure, capability, authority, persistence, enforcement, and uncertainty in this deployment.
2. A finding another engineer can inspect names actor, source, transformation, authority, preconditions, consequence, and confidence separately from severity; group variants that share a control requirement.
3. Evaluate a control at its enforcement point; turn findings into policy that names actor, operation, resource, destination, state, and failure behavior.
4. Place dependable enforcement at the resource service and process boundary; provenance and least privilege preserve roles and narrow interfaces; human approval is meaningful only when bound to exact actions and authentic evidence.
5. A fix is complete only with an owner, implementation location, verification method, and evidence of both proposals and effects.

After reading this chapter, we should be able to write inspectable findings, evaluate risk in context, specify enforceable controls, and declare completion only when evidence covers the stated routes.

## 5.1 Five attack stories, one missing check

A review team examines the invoice assistant from [Chapter 4](chapter-04-mapping-influence.md). One reviewer proposes a malicious PDF. Another suggests a misleading email. A third describes poisoned retrieval content, while two more propose a compromised summary and a deceptive agent message.

All five stories may be plausible. They may also lead to the same failure: the payment executor accepts a destination selected from nonauthoritative information. Counting five payloads as five independent vulnerabilities would exaggerate the finding count and obscure the shared remedy.

A scenario describes how something could happen. A weakness describes the failed requirement that permits it. A consequence describes the loss or policy violation that follows. Useful risk analysis connects these concepts while preserving their distinctions—and asks whether the necessary conditions exist. A creative story that requires unavailable permissions is not an actionable finding against the current system.

## 5.2 Apply systematic questions before ranking findings

Start with the system and authority maps from [Chapter 3](chapter-03-system-task-authority.md) and the influence map from [Chapter 4](chapter-04-mapping-influence.md). Apply STRIDE to the relevant components and flows. At AI-mediated decisions, examine which sources can affect the selected operation, target, arguments, or sequence.

Do not limit the actor inventory to anonymous outsiders. Consider authenticated customers, compromised staff accounts, malicious extension authors, affected service providers, and agents using existing permissions outside their task. Also consider mistakes by legitimate users and unsafe goal pursuit without an injected instruction.

The starting points below illustrate questions that keep that inventory broad.

| Starting point | Example question |
|---|---|
| External actor | Can uploaded content affect another customer's transaction? |
| Authenticated user | Can a valid account request operations beyond its entitlement? |
| Extension author | Can a skill influence a privileged action or execute code directly? |
| Compromised service | Can a tool response redirect later data access? |
| Agent behavior | Can pursuit of the assigned goal cause use of an unintended capability? |
| Operational error | Can stale policy or configuration produce the same consequence accidentally? |

An agent with valid credentials can act from an authorized execution position. That does not make every agent malicious. Credentials and model behavior require separate constraints.

Conventional failures remain in scope. A public storage bucket, broken tenant filter, or vulnerable parser may expose data without an AI decision. Influence-first adds analysis; it does not justify skipping ordinary attack surfaces.

## 5.3 Write a finding another engineer can inspect

A finding should identify the actor, source, transformation, authority, preconditions, and prohibited consequence. It should also distinguish what has been observed from what remains assumed.

For the invoice example, a useful statement is: a supplier-controlled bank field can become the payment destination because the request builder copies it into the transaction and the executor does not compare it with an approved supplier record. This can redirect payment if the attacker controls an accepted invoice and the request reaches execution.

That statement is stronger than “prompt injection may cause financial loss.” It identifies the implementation relationship and tells the engineer what to inspect. If the executor does perform the comparison, the finding must be revised or rejected.

The fields below state what evidence a complete finding should carry.

| Field | Evidence expected |
|---|---|
| Reachable source | Upload rights, tool response access, or a documented data-writing route. |
| Relevant transformation | Code, contract, or trace showing how the source reaches the decision. |
| Available authority | Actual credential and operation scope. |
| Failed requirement | Missing, bypassed, or incorrectly implemented policy check. |
| Consequence | Concrete disclosure, modification, disruption, or other prohibited effect. |
| Confidence | Architecture hypothesis, inspected weakness, controlled demonstration, or observed incident. |

Severity and confidence should not be merged. A serious possible consequence with uncertain reachability may require urgent investigation. A fully reproduced cosmetic error may be low priority. Record both dimensions so uncertainty does not silently disappear inside a score.

## 5.4 Group findings by control requirement and evaluate risk

Group variants when they exploit the same missing check and require the same remediation. Keep variants as tests so the fix must cover them. Split findings when different authority, persistence, owners, or enforcement failures require distinct action.

A document-selected payment destination and a script that directly accesses payment credentials may cause similar losses but require different controls. The first concerns transaction authorization. The second concerns execution privileges and credential exposure. Combining them into “malicious content” would make remediation ambiguous.

A threat record can contain one primary weakness and several delivery paths. State whether the proposed control covers every path. Avoid promising that one filter will address routes that bypass the model entirely.

The practical risk question is what could happen in this system under plausible conditions. Start with the consequence, then examine exposure, attacker control, reachable authority, and existing enforcement. A broad service credential may enlarge the loss; a strict limit may bound it, though repeated operations can still accumulate; a rarely used feature can matter if it permits persistent access or affects a critical asset.

The dimensions below keep that evaluation tied to the deployment.

| Dimension | What to establish |
|---|---|
| Impact | Data scope, financial amount, service interruption, or affected business decision. |
| Exposure | Which users or external sources can reach the path and under what conditions. |
| Capability | What the actor must control or obtain. |
| Authority | The operations and resources reachable after influence succeeds. |
| Persistence | Whether the effect survives sessions, deployment, or revocation. |
| Enforcement | Whether an independent control prevents the consequence. |
| Uncertainty | Missing evidence that could change the assessment. |

A narrative rating is often more useful than an unsupported probability. “External suppliers can reach the path; execution has no destination binding; payments are capped per order but repeat across orders” is actionable. “Risk equals 8.7” is not, unless scoring method and inputs are defined.

CVSS v4.0 can support assessment of a particular vulnerability when its metric groups are used as specified—not as an invented score for an entire agent. Business exposure, cumulative effects, and organizational priorities still need their own analysis. [1]

## 5.5 Documented cases: mechanism knowledge and adaptive testing

Two research cases inform how we generate scenarios and evaluate defenses. They do not justify a high risk rating merely because an application uses a language model.

InjecAgent evaluates indirect prompt injection through tool responses in tool-integrated agents, distinguishing legitimate tasks from attacker-desired outcomes. This supports treating a tool result as a potential source of later decision influence—without establishing exploitability in every product using tools. [2]

Zhan and colleagues study attacks adapted to defenses against indirect prompt injection. Their results challenge conclusions drawn only from fixed, previously known attack strings. This is experimental evidence about evaluated defenses, not proof that all possible controls fail. [3]

For the invoice review, these cases motivate testing several delivery routes against the actual boundary. The rating must follow reachable authority and policy failure.

## 5.6 Choose a response—then turn it into enforceable policy

A review can remove a capability, restrict its scope, introduce enforcement, redesign the workflow, or accept a bounded residual risk. Every accepted response should name an owner and a way to establish completion.

Suppose direct editing of supplier bank details is unnecessary for invoice processing. Removing that tool from the assistant reduces the relevant surface. The payment service should still enforce destination policy, because other clients or future features may reach the same operation.

If the organization accepts a remaining risk, document the exact conditions, owner, scope, and expiration. “Accepted for the launch” alone is incomplete.

Next, turn the chosen response into a policy statement. Begin with the prohibited effect. For the reporting agent from [Chapter 2](chapter-02-understanding-influence.md): restricted customer records may be read only for the authorized account scope and written only to approved internal destinations. Third-party skills may not create new data-sharing permissions.

The policy should identify the actor, operation, resource, destination, and relevant state—and define failure behavior when those facts cannot be established. A network timeout or missing policy record should not silently become permission.

The policy elements below make that statement concrete for the reporting example.

| Policy element | Reporting example |
|---|---|
| Actor and task | Reporting service acting for a named customer-support task. |
| Resource | Records within the authorized tenant and report scope. |
| Operation | Read selected fields, calculate aggregates, write a report. |
| Destination | Approved internal storage with the appropriate access controls. |
| State | Current task authorization and live destination policy. |
| Failure behavior | Stop the consequential operation and report the missing condition. |

A policy may legitimately allow external transfer for another task. That requires a separate authorization path with defined recipients and data scope. A model's explanation that the transfer is necessary cannot create the exception.

## 5.7 The warning works, but the data still leaves

The reporting agent now has an additional instruction: never send customer records to an external service. In a demonstration, it refuses a skill's request to perform external validation. The team concludes that the problem is fixed.

A later run executes the skill's helper program. That program reads the same records and initiates its own connection. The model's refusal never reaches the operating system as an enforceable restriction. The instruction route is discouraged, but the executable route remains open.

A control must be evaluated at its enforcement point. A behavioral rule tells a model what it should do. An execution boundary determines what an operation can do even when behavior is wrong.

The objective is not to remove behavioral guidance. Clear instructions, trained safeguards, and detection can reduce unsafe proposals. The objective is to prevent those proposals—and alternative executable paths—from causing prohibited effects.

## 5.8 Place controls where authority is exercised

The most dependable enforcement point is often the service that owns the resource or effect. The data service can enforce tenant access. The report store can enforce destination and sharing policy. The execution environment can restrict file and network access.

A harness-level wrapper can add useful checks, but it must not be the only route to the protected operation. If a subprocess, plugin, or alternate client can reach the same resource directly, either the resource enforces equivalent policy or that route must be constrained.

The layers below each contribute something different and raise a coverage question.

| Layer | Control contribution | Coverage question |
|---|---|---|
| Model guidance | Reduce unsafe interpretations and proposals. | What happens when the model does not follow it? |
| Harness mediation | Validate proposed tools and arguments. | Can execution bypass the mediator? |
| Resource service | Authorize actual reads and writes. | Does every endpoint apply the rule? |
| Process isolation | Restrict scripts, files, credentials, and network access. | Can a child process or shared mount escape the intended scope? |
| Monitoring | Detect unexpected effects and policy failures. | Is evidence independent of the agent's account? |
| Recovery | Revoke access and restore trusted state. | Can retained state reintroduce the behavior? |

Defense in depth should have distinct failure assumptions. Two similar-text classifiers are not the same independence as a destination restriction in the execution environment. Count coverage of the effect, not the number of tools labeled “guardrail.”

## 5.9 Preserve meaning, narrow authority, and make approval meaningful

Provenance records where information came from. It helps an approver distinguish a customer claim from an internal decision. It does not prove that a source is truthful or entitled to authorize an operation.

Preserve source roles across transformation. A summary may state that a skill requests external validation; it must not convert that into “external validation approved.” Structured fields keep the claim and the authoritative decision separate.

Least privilege should be expressed in operations and resources. A tool named “report” may still expose arbitrary code execution or unrestricted destinations. Review the actual arguments and side effects. A useful design may return an opaque report handle instead of raw records, with the storage service resolving that handle under policy.

Human approval should concern a concrete action—recipient, data scope, amount where relevant, and the source of the authorization requirement. Bind approval to the exact operation; if the agent changes protected fields after approval, require a fresh decision. Define expiration and revocation for asynchronous work.

Approval is not a substitute for controls on actions the user is never entitled to authorize. A customer cannot approve disclosure of another customer's records. Avoid approval fatigue: repeated generic “continue?” prompts teach users to accept without understanding the consequence.

## 5.10 Documented cases: architectural enforcement

Two research architectures support placing policy outside ordinary model interpretation. The controls proposed for our reporting agent are engineering choices informed by these ideas; they have not been experimentally validated in this book.

CaMeL separates selected processing responsibilities and applies policies around information and tool use. Its evaluation supports constraining selected prompt-injection consequences by design, within stated scope and assumptions—not as a universal guarantee. [4]

Progent studies privilege control for agent tools through explicit policies, separating a proposed action from permission to execute it. This supports examining operation and argument scope while leaving policy correctness to the system design. [5]

The design must be tested against its own alternate execution routes and business requirements.

## 5.11 Define evidence before declaring the fix complete

A control requirement needs an owner, an implementation location, and a verification method. “Add a guardrail” leaves all three unclear. “The report executor rejects destinations outside the approved tenant store, including helper-process routes” is a testable requirement.

The requirements below pair each obligation with an owner and evidence.

| Requirement | Owner | Evidence |
|---|---|---|
| Only authorized records are readable | Data-service team | Cross-tenant requests fail at the data service. |
| External skill cannot transfer raw records | Runtime team | Synthetic transfer attempts fail from tools and subprocesses. |
| Report sharing remains scoped | Storage team | Resulting object's access policy matches the task. |
| Approval cannot be reused for changed actions | Workflow team | Modified and expired requests are denied. |
| Suspicious state cannot survive cleanup unnoticed | Operations team | Recovery checks include retained memory and artifacts. |

Tests should target boundary conditions as well as a known attack string—missing identities, stale approvals, changed recipients, bulk endpoints, retries, and subprocess execution—while verifying authorized task completion. Execution evidence matters: a denial message followed by a successful network transfer is a control failure; a blocked proposal is a different result. Record both proposal and effect.

## 5.12 Return to the five stories and the reporting agent

The invoice team consolidates four source variants into one transaction-authorization finding. The direct helper-script route remains separate because it relies on different credentials and execution access.

| Finding | Risk reasoning | Proposed response |
|---|---|---|
| Unverified content determines destination | Externally reachable source can affect a consequential transaction field. | Resolve destination from approved state and bind approval to exact fields. |
| Helper can access payment credentials | Executable extension can bypass the ordinary request path. | Remove credential access, isolate execution, and mediate required operations. |
| Summary loses source role | Makes the first failure easier to trigger and harder to review. | Preserve role metadata; track as a contributing condition and test variant. |

Validation should attempt document, email, retrieval, and agent-message variants against the transaction boundary, and test direct execution separately. Legitimate payments must still complete.

For the reporting agent, tenant-scoped access, a credential-limited helper, and destination handles at write time constrain prohibited disclosure even if the skill still recommends an unsafe procedure.

| Test route | Expected behavior |
|---|---|---|
| Skill asks for external transfer | No restricted data leaves approved destinations. |
| Helper initiates direct transfer | Runtime restriction prevents the operation. |
| Tool selects another tenant's data | Data service rejects the request. |
| Approval is followed by a changed recipient | Executor rejects the changed operation. |
| Valid report is requested | Report completes with correct access policy. |

A completed control record states the tested version and remaining gaps. Success is whether owners can understand failures, implement controls, and produce evidence—not how many imaginative attacks were listed. [Chapter 6](chapter-06-apply-across-layers.md) applies the same questions across layers; [Chapter 7](chapter-07-complete-design-review.md) and [Chapter 9](chapter-09-assure-continuously.md) cover design review and continuous assurance.

## Appendix 5A — Finding quality and control specification

Score findings for specificity, supported preconditions, material consequence, distinctness, and feasible remediation—not for influence-first terminology. Retain rejection reasons: unavailable permission, unreachable source, effective enforcement, unsupported consequence, or duplicate requirement.

Write each control as: under these preconditions, this component permits these operations and rejects these alternatives. Identify policy inputs, failure behavior, owner, evidence source, and change triggers. Include negative, legitimate-task, and alternative-path tests. Record residual uncertainty separately. Shared templates appear in the [appendices](appendices.md).

## Appendix 5B — Additional reading

Use InjecAgent [2] and adaptive-attack research [3] for evaluation limits; FIRST [1] for CVSS; CaMeL [4] and Progent [5] for architectural separation and privilege policies. Risk tables here are proposed review aids, not a published scoring standard.

## References

1. FIRST. [CVSS v4.0 Specification Document](https://www.first.org/cvss/v4.0/specification-document).
2. Qiusi Zhan et al. [InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents](https://arxiv.org/abs/2403.02691). 2024.
3. Qiusi Zhan et al. [Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents](https://arxiv.org/abs/2503.00061). 2025. Experimental defense evaluation.
4. Edoardo Debenedetti et al. [Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813). CaMeL, 2025.
5. Tianneng Shi et al. [Progent: Securing AI Agents with Privilege Control](https://arxiv.org/abs/2504.11703). Research on agent privilege policies.
