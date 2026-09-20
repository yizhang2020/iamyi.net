# Chapter 4 — Map Influence Across Decisions and Boundaries

*Trace influence. Bound authority.*

## Overview

A high-level diagram such as “invoice to AI to payments” does not show whether a supplier-controlled field can redefine a payment destination. Influence mapping must follow extraction, summarization, request construction, approval, and execution—and it must show the authoritative records that should constrain those steps. Without forward and backward traces, and without clear labels for flow versus dependence versus authority, findings either invent paths or treat architecture reachability as proven effect.

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. Keep familiar data-flow elements and add decision points and source roles where they explain consequential behavior.
2. Forward traces start from what an actor can change; backward traces start from a prohibited consequence and work toward required conditions.
3. Flow, dependence, and authority overlap but are not interchangeable; evidence labels should match what has actually been shown.
4. Persistence, consumers, and alternative routes (batch endpoints, scripts, shared stores) belong on the map when the implementation permits them.
5. A control-aware map yields implementation questions and tests tied to identifiable boundaries, versioned with the system.

After reading this chapter, we should be able to build an influence map for a consequential workflow, distinguish evidence levels along a path, and turn that map into control-aware tests.

## 4.1 The invoice takes a longer route than expected

An accounts-payable assistant receives an invoice from a supplier. It extracts the amount, order reference, and banking details. A summarizer produces a short payment recommendation. Another component creates a payment request for a human approver.

The invoice includes a note saying that the supplier has changed banks. The summary preserves the new account number but omits that the change came only from the invoice. The approval screen displays the number as the supplier's current payment destination. If the approver accepts it, the payment may go somewhere the supplier's verified record never authorized.

This is a hypothetical example. It does not assume the invoice is malicious or that the final transfer succeeds. It asks whether a supplier-supplied document can redefine the destination used by the payment system.

A diagram showing “invoice to AI to payments” would not answer that question. The review needs extraction, summarization, destination selection, approval, and execution—plus the verified supplier record that should constrain the destination.

## 4.2 Start with an ordinary system map

A data-flow diagram shows processes, external entities, stores, flows, and boundaries. Keep those familiar elements. Add decision points and source roles where they help explain how information affects consequential behavior.

The map should be detailed enough to identify enforcement. It does not need to reproduce every function or prompt token. Split a large workflow into an overview and focused views when one picture becomes difficult to read.

For the invoice system, the overview includes the supplier, upload service, parser, assistant, supplier registry, approval service, payment executor, and audit store. The focused view examines how a proposed bank destination becomes an approved transaction.

The map elements below are what a useful record should capture for each consequential path.

| Map element | Record |
|---|---|
| Source | Who controls the invoice and its attachments. |
| Transformation | Extraction and summary operations, including version and retained attribution. |
| Decision | Selection of supplier, amount, destination, and approval route. |
| Authority | Identities and permissions used by approval and payment services. |
| Store | Supplier registry, queued request, approval record, and retained conversation. |
| Consumer | Human approver, payment API, notification system, and future retrieval. |
| Boundary | Where a source's claim must be checked against an authoritative record. |

The same physical component can perform several roles. A harness may retrieve a document, summarize it, and construct a tool request. Represent the distinct decisions when they involve different policy requirements.

## 4.3 Trace forward from a controlled source

Forward analysis begins with what an actor can change. In our example, the actor controls the invoice text. That control does not automatically extend to the supplier registry, approval service, or payment account. The purpose of the trace is to determine whether the application connects those capabilities improperly.

At each step, record the carrier and the decision it can affect. The extracted bank field becomes an input to summarization. The summary becomes an input to request construction. The generated request becomes an input to the approval display and payment executor.

The important evidence is whether each connection exists. Does the parser extract the note? Does the summarizer retain the account number? Does the request builder select it over the registry value? Does execution permit a destination that differs from the approved supplier account?

The candidate dependencies below show what evidence would confirm or break each step.

| Step | Candidate dependency | Evidence needed |
|---|---|---|
| Upload to extraction | Invoice text becomes a bank field. | Parser output for the versioned test document. |
| Extraction to summary | Bank field appears without source qualification. | Input/output records for the summarizer. |
| Summary to request | Generated destination uses the summarized field. | Request-construction logic or controlled trace. |
| Request to approval | UI presents the destination as established information. | Actual approval payload and display. |
| Approval to execution | Executor sends funds to that destination. | Authorization rules and controlled payment result. |

A weak link can invalidate the proposed scenario. If the payment executor always resolves the destination from a verified supplier ID, a generated bank number may never become actionable. Record that as a control, not an inconvenient exception to the story.

## 4.4 Trace backward from a prohibited consequence

Backward analysis starts with an outcome: funds reach an unverified account. Ask what operation would cause it and what conditions that operation requires. Then work toward the information and authority that could satisfy those conditions.

An unauthorized destination requires a payment request that names or resolves to that destination. It may also require approval. The next questions concern how the request was built and whether approval was tied to its exact fields.

The backward route may reveal a path the forward route missed. A supplier registry update tool might permit the assistant to change the account before requesting payment. Execution could then correctly use the registry while the registry itself has been improperly modified.

Forward and backward traces strengthen each other when they meet on the same preconditions and evidence. Their agreement is not proof by itself. Both may share a mistaken assumption—for example, believing the assistant can call a registry update it cannot actually invoke.

## 4.5 Distinguish flow, dependence, and authority

A flow records movement. A dependency records that a decision may change when an input changes. Authority records what the acting component can do. These relationships overlap, but they are not interchangeable.

A document may flow into context without changing the selected account. A bank-change statement may affect a decision even after its exact words disappear. A decision may be unsafe while the payment service still blocks execution.

Use labels that describe evidence rather than certainty by appearance. These labels align with the exposure, behavioral influence, and security-consequence stages in [Chapter 2](chapter-02-understanding-influence.md).

The evidence labels below keep those distinctions visible in a finding.

| Evidence label | Meaning |
|---|---|
| Architectural path | The design permits information to reach the decision. |
| Observed exposure | A particular run included the source. |
| Observed behavioral change | A specified decision differed under a documented comparison. |
| Blocked proposal | A prohibited operation was requested but denied. |
| Demonstrated consequence | A controlled test or incident record establishes the effect. |

This vocabulary supports disagreement. One reviewer may accept the architecture path while requesting better evidence for behavioral influence. The finding can preserve both judgments without pretending the entire chain is confirmed.

## 4.6 Include persistence, consumers, and alternative routes

A completed map extends beyond the initial response. The summary may enter memory or a search index. A notification may be copied into a ticket that a second assistant reads. A rejected proposal may still leave a misleading supplier note in a shared store.

Mark these feedback paths only when the implementation permits them. Logging does not automatically train a model. A memory entry does not necessarily become a trusted instruction. Specify how and when stored material is read again.

Alternative routes matter equally. A payment helper script may bypass the normal API wrapper. A batch endpoint may use different authorization logic from the interactive endpoint. A human approval workflow may check amounts while failing to bind the destination.

The map is complete enough for a finding when it identifies the consequential routes and the controls that cover them—not merely because all AI-related boxes have been highlighted.

## 4.7 Documented case: indirect instructions through external material

Greshake and colleagues demonstrated indirect prompt injection in LLM-integrated applications through externally supplied content. Their work supports looking beyond the legitimate user's prompt to information encountered while performing the task. It is attack research, not a comparative study of influence-first mapping. [1]

The invoice scenario applies that broader concern to business authority. Its particular parser, registry, and payment behavior remain hypothetical. The mapping procedure identifies what would need to be inspected before asserting that this scenario is exploitable.

## 4.8 Return to the invoice with a control-aware map

The revised design separates proposed invoice facts from verified supplier facts. The assistant can flag a bank-change request, but cannot silently update the registry. A designated verification workflow handles destination changes, and the payment executor checks the current approved destination.

Approval is bound to the exact supplier, amount, currency, destination, and request version. A change to any protected field invalidates the approval or requires a fresh policy decision.

The candidate paths below pair each risk with a proposed boundary and a test.

| Candidate path | Proposed boundary | Test |
|---|---|---|
| Invoice supplies new destination | Registry defines payment destination | Bank note does not change executed destination. |
| Summary loses attribution | Structured source roles remain separate | Summary cannot create a verified registry value. |
| Request changes after approval | Approval binds exact transaction fields | Modified request is rejected. |
| Assistant updates registry first | Destination changes require independent verification | Ordinary assistant identity cannot perform the change. |
| Batch or script bypass | Equivalent policy covers alternative execution routes | Direct and batch attempts obey the same restriction. |

The analysis produces implementation questions and tests tied to identifiable boundaries. If the registry change workflow already enforces these rules, record that evidence and focus elsewhere.

The result remains versioned. A later tool addition that permits supplier updates changes the map even if the diagram's major components remain the same. [Chapter 9](chapter-09-assure-continuously.md) returns to how such changes trigger renewed review. [Chapter 5](chapter-05-threats-controls-and-evidence.md) turns these paths into findings, controls, and evidence.

## Appendix 4A — Mapping notation and review exercise

Use ordinary data-flow notation for components and stores. Add short annotations for source role, decision affected, executing identity, and enforcement owner. Avoid labeling every edge “untrusted”; say what that source is allowed to establish. A mapping record can use: source, transformation, decision, requested operation, enforcement, effect. Include persistence and alternative routes as separate records when they change the control requirement.

Ask a second reviewer to select one prohibited consequence, reconstruct its prerequisites from the map alone, and identify the control that interrupts each route. If they must invent identities, approval semantics, or hidden stores, improve the map before treating it as evidence. For additional reading, use the indirect-injection study [1]; return to [Chapter 2](chapter-02-understanding-influence.md)'s evidence labels when distinguishing exposure from causation.

## References

1. Kai Greshake et al. [Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://arxiv.org/abs/2302.12173). 2023. Controlled attack research.
