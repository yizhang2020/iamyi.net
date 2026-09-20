# Chapter 3 — Define the System, the Task, and the Authority

*Trace influence. Bound authority.*

## Overview

A convincing demonstration of an AI assistant is not a security specification. Until we bound the task, inventory the real components, and separate configured permission from authorized purpose, later influence analysis has nothing concrete to evaluate. Vague requests such as “review the prompt” leave ownership, approval, and payment authority undefined.

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. A useful task statement identifies the actor, desired result, resources, restrictions, and a safe stopping point.
2. An architecture inventory must name deployed components and responsibilities—“the AI” is too broad to place a control.
3. Configured permission (what a credential will accept) can diverge from authorized purpose (what should happen for a particular task).
4. Each source may establish some facts and must not independently establish others; assumptions about those roles need an owned register.
5. The first deliverables of review are a system description, an authority map, and an assumption register—before hunting for attacks.

After reading this chapter, we should be able to write a bounded task, inventory the system that implements it, map authority for consequential actions, and turn uncertainty into owned questions.

## 3.1 “Handle the refund” is not a security specification

A product team wants a support assistant to handle refunds. The demonstration looks convincing: the assistant reads a complaint, finds an order, explains the policy, and offers a refund. The team asks security to review the model prompt.

The first useful questions concern the workflow. Which purchases are refundable? Who owns the order? Who can approve an exception? Can the assistant execute a refund or only recommend one? Where does the money go?

This hypothetical system recurs throughout the book. Its assistant serves authenticated customers, retrieves order records and policy documents, and submits refund requests. A separate payment service performs the financial operation. Customer attachments may explain a complaint, but they cannot establish ownership or approval—the same role distinction [Chapter 1](chapter-01-influence-first-security.md) introduced with a false approval claim in a summary.

That division is a design choice, not an observation about an existing product. The review must make its promises and limits explicit before looking for attacks.

## 3.2 Write the task as a bounded commitment

A useful task statement identifies the actor, desired result, resources, and restrictions. For this example: help an authenticated customer understand an order and request an eligible refund to the original payment method. Escalate exceptions to a designated approver. Do not change ownership, payment destinations, or approval policy. Eligibility comes from a policy version and authoritative transaction state; exceptions require a different authority; payment destination is established by the original transaction, not a document in the conversation.

The proposed definition below makes those boundaries inspectable.

| Item | Proposed definition |
|---|---|
| Intended user | An authenticated customer acting on their own eligible order. |
| Intended result | A policy explanation, a refund request, or a clear escalation. |
| Protected assets | Customer records, company funds, approval records, and service capacity. |
| Permitted evidence | Order facts, approved policy, and customer statements clearly labeled as statements. |
| Prohibited effects | Cross-customer disclosure, unauthorized payment, destination substitution, and duplicate refund. |
| Safe stopping point | Explain the limitation and hand off without expanding privileges. |

A safe stopping point is part of the specification. If the product requires the agent to “always finish,” failures may become pressure to invent another route. Treat a justified refusal, escalation, or request for missing information as a legitimate outcome.

Unacceptable outcomes should include more than catastrophic losses. Excessive data access, misleading approval status, and repeated small refunds can matter. Record when each consequence is material rather than importing a generic severity label.

## 3.3 Inventory the actual system

An architecture inventory should identify deployed components and responsibilities. “The AI” is too broad to tell an engineer where to place a control. The model produces interpretations and proposals; the harness manages execution; application services enforce business operations; connected agents or people may contribute separate decisions.

The components below illustrate roles and security-relevant state for the refund assistant.

| Component | Role | Security-relevant state |
|---|---|---|
| Identity service | Establish customer session and account context. | User identity, session validity, tenant membership. |
| Support application | Accept requests and show results. | Conversation, task ID, requested order. |
| Retrieval service | Return relevant approved policy material. | Corpus versions, access filters, document provenance. |
| Model and harness | Interpret requests and propose permitted tool calls. | Model version, instructions, context, tool configuration. |
| Order service | Return scoped transaction facts. | Ownership, payment reference, remaining refundable amount. |
| Approval service | Record authorized exceptions. | Approver identity, exact scope, expiration, revocation. |
| Payment service | Execute validated refunds. | Transaction state, recipient binding, deduplication record. |
| Audit service | Preserve evidence of consequential operations. | Correlated decisions and effects with controlled retention. |

External dependencies belong in the inventory when they affect the review—hosted models, skill registries, logging platforms, or support integrations. Record what crosses the relationship and who can change it. Also identify development and operational access: an administrator who can replace a prompt, change a retrieval filter, or install a skill alters the behavior available to users.

OWASP's threat-modeling guidance treats understanding system components, flows, stores, and trust boundaries as foundational. The inventory here applies that principle to an AI-assisted business workflow. [1]

## 3.4 Separate configured permission from authorized purpose

A credential describes what a system will accept under its current rules. The human-authorized task describes what should happen for a particular purpose. Those can diverge without a software exploit.

Suppose the payment tool permits refunds for any order in the company, while a customer session permits access to one account. Passing the tool a different order may be technically possible while violating the customer's authorized scope. The service credential must not erase the original task boundary.

For every consequential action, identify the principal whose credential performs it, the user or task represented, the source that establishes the target, and the service that checks policy.

The map below applies that idea to the refund workflow.

| Action | Technical actor | Authoritative evidence | Enforcement owner |
|---|---|---|
| Read order | Scoped order-service client | Session identity plus order ownership | Order service |
| Explain policy | Assistant | Approved policy version | Retrieval and application owners |
| Recommend refund | Assistant | Order facts and policy | Application |
| Approve exception | Designated approver | Approval record bound to the request | Approval service |
| Execute refund | Payment-service identity | Valid request, current eligibility or exception, remaining balance | Payment service |

A recommendation and an approval are different operations. If the UI shows both using the same status field, the implementation invites confusion. Give each state an explicit owner and transition rule.

Authority can also be revoked. Decide which conditions must be rechecked at execution and how queued work responds when an approval expires or access is lost. A correct decision at request time may be stale by the time an operation runs.

## 3.5 Decide what each source can establish

Policy documents, customer messages, and order records all contain useful information. Their roles differ. A customer message can establish what the customer reports. An order record can establish the recorded payment amount. A current approved policy can define eligibility conditions.

A retrieved sentence saying “exceptions are permitted” does not identify who approved this exception. A screenshot of an approval screen is not automatically an approval record. A summary that merges both should preserve the distinction rather than produce an unqualified “approved” status.

The source roles below show what each source may and must not independently establish.

| Source | May establish | Must not independently establish |
|---|---|---|
| Customer complaint | Alleged problem and requested remedy | Ownership of another order |
| Uploaded invoice | Claimed transaction details | Current payment destination |
| Approved policy corpus | Published eligibility rules | That an exception was granted |
| Order service | Current recorded transaction facts | A new policy exception |
| Approval service | A scoped, valid approval | Permission beyond its recorded scope |
| Agent summary | A derived explanation with provenance | A new authoritative fact by confidence alone |

State assumptions explicitly. If a policy repository is treated as authoritative, who can publish to it? If order ownership is cached, how old can it be? If a hosted tool preserves identity context, what evidence supports that claim?

## 3.6 Documented case: tasks and permissions in agent evaluation

AgentDojo evaluates agents carrying out user tasks while encountering adversarial material, separating legitimate task completion from attacker objectives. That separation is a useful reference for defining success and failure. It is not a production refund system or proof that this chapter's authority map improves review performance. [2]

“The assistant completed the conversation” is an inadequate success criterion. Distinguish a correctly completed refund, a justified escalation, and an unauthorized payment that merely looks helpful.

## 3.7 Turn uncertainty into an owned question

Reviews often stall because an assumption is repeated as a fact. “The backend checks that” may mean the speaker has seen code, read an old design, or simply expects the check to exist. Record the difference.

Use a small assumption register: proposition, supporting evidence, responsible owner, and what changes if it is false. Questions that determine whether a serious consequence is reachable should be resolved before the design is accepted.

The register entries below illustrate how to own those questions for the refund system.

| Assumption | Evidence requested | Consequence if false |
|---|---|---|
| Every order read is scoped to the current customer. | Endpoint authorization logic and cross-account tests. | Customer-controlled identifiers can disclose other accounts. |
| Refund destination comes from the original payment. | Payment request contract and execution logic. | Untrusted content may redirect funds. |
| Exceptions require a live approval record. | Approval schema and execution-time validation. | Summaries or stale approvals may authorize payment. |
| Retries cannot create duplicate refunds. | Transaction and deduplication behavior. | Repeated execution can exceed the intended amount. |

An unresolved assumption is not automatically a vulnerability. It is a gap in the security argument. The review can proceed with a conditional finding while stating what remains to be inspected.

## 3.8 Return to the refund request

The initial request to “review the prompt” has become a bounded system review: what the assistant may accomplish, which sources establish facts, and where authority must be checked.

Deliverables are a system description (task, architecture, assets, data movement, deployment boundaries), an authority map, and an assumption register. Validation begins with contract-level questions: cross-customer order reads fail; refunds to a new destination fail under policy; valid exceptions identify approver and scope; tasks lacking evidence stop or escalate without broader access.

These are proposed checks for the hypothetical architecture. [Chapter 4](chapter-04-mapping-influence.md) maps how customer content can reach each decision.

## Appendix 3A — System description template

Record purpose, intended users, protected assets, unacceptable effects, system boundary, component owners, external providers, and data retention. Include development and operational identities. Name the approved model, harness, tool, skill, and policy versions. For each action, record the user represented, execution principal, operation, resource, relevant state, policy source, enforcement owner, and expected behavior when evidence is unavailable. Shared templates also appear in the [appendices](appendices.md).

## Appendix 3B — Additional reading

Use OWASP [1] to check whether the description covers the whole system. Use AgentDojo [2] for separating legitimate tasks from adversarial objectives. Business policy itself must come from the organization operating the application.

## References

1. OWASP. [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).
2. Edoardo Debenedetti et al. [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://arxiv.org/abs/2406.13352). Controlled evaluation environment, 2024.
