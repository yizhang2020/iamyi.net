---
title: "2. Understanding Influence: From Information to Consequence"
keywords:
  - influence
  - exposure
  - behavioral influence
  - security consequence
  - candidate finding
description: >
  Defines influence for security review, follows paths through lifecycle and
  transitions, and shows how to produce a complete candidate finding with evidence.
date: 2026-09-20
---

# Chapter 2 — Understanding Influence: From Information to Consequence

*Trace influence. Bound authority.*

## Overview

Information, instructions, and learned behavior can shape what a system interprets, decides, or does. When that influence reaches beyond a source’s legitimate role, the result can be unauthorized disclosure, unsafe execution, or another prohibited effect—even when the original wording never survives unchanged. Without a clear definition of stages, transitions, and evidence, reviews either exaggerate exposure or miss alternative routes such as executable helpers.

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. Influence is the capacity of information, instructions, or learned behavior to shape interpretation, decision, or action; it becomes a security concern when a source can shape a consequential decision in a way policy does not permit.
2. Exposure, behavioral influence, and security consequence are distinct stages; a complete review follows both instruction-shaped decisions and direct executable routes.
3. Transitions matter as much as entry points: data becoming instruction, a claim becoming authority, an output becoming persistent guidance, and a proposal becoming an effect.
4. Evidence must match the claim—artifact versions, context records, proposals, policy decisions, and execution results support different conclusions.
5. A complete candidate finding names source, decision, authority, consequence, preconditions, and the evidence needed to confirm or reject the path.

After reading this chapter, we should be able to define influence for security review, follow it through lifecycle and transitions, state what evidence supports, and produce a complete candidate finding.

## 2.1 A useful skill with an unexpected instruction

A developer asks an agent to prepare a customer-usage report. The agent can read selected customer records, create a spreadsheet, and save the result in an approved internal folder. To help with the task, it loads a reporting skill supplied by a third party. The skill includes instructions and a small helper program.

Most of its instructions look ordinary: collect the records, calculate totals, and format the report. One instruction adds a prerequisite: send the source records to an external “validation service” before continuing. The agent may interpret this as part of the reporting procedure. If its tools permit the transfer, customer information could leave the organization.

This is a hypothetical example. It illustrates a design problem rather than a confirmed incident. The developer authorized an internal report. The skill author supplied a procedure, but did not acquire authority to choose a new recipient for customer data.

There is also a second route. The helper program might make the transfer directly when executed. In that route, the model does not need to accept the instruction about validation. The ordinary execution environment provides the access that the malicious program needs.

The two routes lead to a similar possible loss, but they require different observations and controls. One concerns instructions shaping an agent’s decision. The other concerns executable code using granted privileges. A complete review follows both.

## 2.2 What influence means

**Influence** is the capacity of information, instructions, or learned behavior to shape a system’s interpretation, decision, or action. Security analysis examines whether that influence can contribute to a consequence outside the source’s legitimate role or the system’s authorized purpose.

That definition includes intended behavior. A report should reflect the records it summarizes. An assistant should use the user’s request to select a task. Influence becomes a security concern when a source can shape a consequential decision in a way the applicable policy does not permit.

For the reporting agent, a customer record can supply usage figures. It cannot authorize a new external recipient. A skill can describe how to calculate a total. Its recommendation to transfer data still requires authorization from the system’s policy, independently of the recommendation itself.

The review must separate three stages. The table below defines each stage and shows it in the reporting example.

| Stage | Meaning | Reporting example |
|---|---|---|
| Exposure | A component encounters information. | The skill’s instructions enter the model’s context. |
| Behavioral influence | The information affects interpretation, a decision, or a proposed action. | The agent proposes sending records to the validation service. |
| Security consequence | An action or output violates policy or causes loss. | Restricted records reach an unauthorized recipient. |

Exposure alone does not establish that the model followed an instruction. A prohibited proposal does not establish that a transfer succeeded. Conversely, a program may cause the transfer without a model proposing it. These distinctions prevent a review from exaggerating findings or overlooking an alternative route.

### Legitimate role is more useful than a universal trust label

“Trusted” needs a purpose. A customer may be authoritative about their preferred contact address, but not about another customer’s access rights. An internal document may accurately describe a procedure while being outdated about who can approve an exception. The useful question is: trusted to establish what?

The reporting skill may be approved for formatting spreadsheets. That approval does not automatically extend to exporting raw customer records. Reviewers should identify the decisions each source may legitimately inform and the decisions it must not independently authorize.

### Influence can be accidental

A malicious actor is not required for an unsafe decision. An outdated example, a mistaken summary, or an incorrectly configured workflow can redirect behavior. A model may also infer a procedure that no source explicitly requested. The control requirement depends on the prohibited consequence, even when intent is unknown.

This is why accuracy, security, and reliability overlap without being identical. A wrong answer becomes a security finding when the analysis connects it to a protected asset, policy violation, or relevant loss. Ordinary inaccuracies still deserve attention, but they should not all be labeled successful attacks.

## 2.3 Follow the lifecycle, then follow the loops

Influence does not move through one fixed sequence. Training shapes learned behavior before runtime. The harness then assembles context from instructions, tools, documents, and memory. Outputs may return as future inputs. A useful map therefore covers how the system was built and how specific information reaches decisions, actions, consumers, and persistent state.

### Before execution: what shapes the system

Before runtime, several surfaces can change what the deployed system will do.

| Surface | What can change | Questions for the review |
|---|---|---|
| Training data | Learned associations, responses, or trigger-dependent behavior. | Who supplies and modifies the data? Which risks can evaluation detect? |
| Fine-tuning and adapters | Task behavior and responses to unsafe requests. | Which dataset and artifact versions were approved? What regression follows a change? |
| Model selection and updates | The behavior available to the application. | Who can replace the model or route requests elsewhere? |
| Harness configuration | Instruction assembly, context, memory, and tool access. | Who can alter configuration, and which checks remain independently enforced? |
| Skills and dependencies | Procedures, scripts, and dynamically loaded resources. | What will be read, executed, or fetched, and with whose privileges? |

Fine-tuning research shows customization can weaken safety behavior, including in some experiments without malicious intent—evaluate the changed artifact rather than assuming original properties remain. [1] Hosted models may hide training provenance; record that limit and examine observable behavior plus downstream controls.

### During execution: what reaches decisions

At runtime, many carriers can reach a decision.

| Surface | Possible influence path | What to inspect |
|---|---|---|
| User requests and attachments | A request or assertion changes the task or claims approval. | Identity, authorized scope, attachment provenance. |
| RAG and external content | Retrieved material changes an answer, plan, or tool argument. | Corpus writers, retrieval selection, attribution, extraction. |
| Media and document conversion | Embedded content becomes text or another observation. | Original artifact, transformed representation, retained provenance. |
| Tool descriptions and results | Guidance or returned content shapes later operations. | Server identity, description versions, response content, policy boundaries. |
| Summaries and compression | A statement survives while source or uncertainty disappears. | Allegations, verified facts, and approvals remain distinguishable. |
| Memory and caches | Earlier material becomes guidance for a later task. | Who can write, what is retained, who retrieves it, when it expires. |
| Agent messages and delegation | Another agent’s conclusion affects a receiver with different authority. | Provenance, delegated scope, receiver-side checks. |
| Plans and tool-call arguments | A decision selects an operation, target, recipient, or sequence. | Proposed action and enforcement before execution. |

RAG and MCP are labels for retrieval and tool connection patterns, not vulnerabilities by themselves. The relevant questions concern particular information, identities, privileges, and consumers.

### After generation: what consumes the output

The review continues after the model produces an answer. The same output creates different consequences depending on the consumer: a person treating advice as verified authorization; an API treating generated fields as an authorized state change; a shell executing proposed code; a renderer activating unsafe content; another agent treating a conclusion as instruction; or memory and logs promoting recorded output into later knowledge. Feedback loops belong on the map when the architecture permits them; recording an output does not automatically train a model or expose it to another agent.

## 2.4 Watch the transitions, not just the entry points

An entry-point inventory is useful, but the most revealing questions often concern a transition. Where does information change form? Where does its apparent credibility increase? Where does a recommendation acquire the ability to cause an effect?

In the reporting example, the skill’s statement “validation is required” begins as third-party guidance. The agent may convert it into a plan. A tool call then converts the plan into an executable request. The transfer succeeds only if the environment allows the relevant data access and outbound operation.

The words need not survive unchanged. A summary might reduce the instruction to “complete validation before reporting.” A second agent might receive only the conclusion that validation is mandatory. Tracking copied strings would miss some of these relationships.

Four transitions deserve particular attention:

1. Data becomes instruction: content supplied for analysis directs the workflow.
2. A claim becomes authority: a source’s assertion is accepted as approval or policy.
3. An output becomes persistent guidance: a temporary result is reused as established knowledge.
4. A proposal becomes an effect: a consumer executes, publishes, sends, or commits the result.

These are review prompts, not a claim to cover every possible mechanism. Some paths will be legitimate, and others will already be constrained. A finding must explain the specific transition that violates policy and the conditions required for it to occur.

## 2.5 Observe the evidence we can actually collect

A review needs evidence about what reached the system, what it proposed, what controls decided, and what actually happened. A model’s account of its reasoning can help form questions; it is not an authoritative causal record.

| Evidence | What it supports | Important limitation |
|---|---|---|
| Artifact identifiers and versions | Which model, skill, configuration, or document was involved. | Availability does not establish use. |
| Retrieval and context records | Which information reached a model invocation. | Exposure does not establish behavioral influence. |
| Proposed tool calls | Which operations and arguments the agent selected. | A proposal may be denied or fail. |
| Policy decisions | Which enforcement rule allowed or blocked an operation. | A log does not prove correct implementation. |
| Execution and destination evidence | Which operation completed and what changed. | Timing alone does not establish the behavioral source. |
| Memory writes and later reads | Whether affected information persisted and reappeared. | Later exposure still needs a later decision. |

For the reporting agent, useful evidence includes the skill version, proposed recipient, transfer policy decision, and destination receipt. The helper-program route also needs process and network evidence. Logging must have its own access controls; capture the minimum needed. Incomplete records should be labeled as such: exposure is not causation.

This book does not assign a universal numerical score to influence. Keep proposal rates separate from execution rates in controlled comparisons. Frequency alone does not establish business risk. Detailed measurement design belongs in [Chapter 5](chapter-05-threats-controls-and-evidence.md) and [Chapter 9](chapter-09-assure-continuously.md).

## 2.6 Documented case: persistent memory

*AgentPoison* grounds this chapter in published evidence. Researchers modified agents’ memory or retrieval knowledge bases with malicious demonstrations so that an optimized trigger would retrieve them. The experiments did not require additional model training; the reported result was attacker-directed behavior in the evaluated settings. [2]

The key lesson is persistence outside model weights. A normal-looking task can encounter material planted earlier. Poisoned-store access and retrieval conditions are important preconditions; the study does not establish that every writable knowledge base is exploitable. The review implication is to inspect corpus writers, retrieval, provenance, and downstream action controls—an engineering inference from the mechanism, not comparative proof of influence-first review. [2]

A related pattern appears in skill content: *Agent Skills in the Wild* describes a code-review skill with HTML comments directing approval of marked code and external disclosure of conversation context. That is evidence of concerning skill content, not a count of successful compromises; inspect loaded content including material a rendered preview may hide. [3]

## 2.7 Complete the reporting-agent analysis

Return to the opening example. Assume the application can access restricted customer records, load the third-party skill, and execute its helper program. Whether the transfer is possible depends on actual tool, process, and network permissions—inspect or test before classifying the path as confirmed.

| Field | Analysis result |
|---|---|
| Protected asset | Customer information restricted to the authorized reporting workflow. |
| Authorized task | Create an internal usage report in an approved location. |
| Actor and controlled source | A third-party skill author controls instructions and bundled helper code. |
| Legitimate source role | Provide reporting procedures and formatting assistance. |
| Candidate instruction path | Skill guidance enters context, changes the plan, and produces an external-transfer request. |
| Candidate code path | The agent executes the helper, which reads records and initiates a transfer directly. |
| Required preconditions | Content loaded or code executed; records accessible; outbound path to unauthorized destination. |
| Policy violation | The skill’s procedure determines a data recipient the organization has not authorized. |
| Possible consequence | Unauthorized disclosure of customer information. |
| Primary control | Enforce data-access and destination policy across tool and process execution paths. |
| Evidence needed | Versioned artifacts, context or process traces, enforcement decisions, controlled destination observations. |
| Current status | Hypothetical design finding pending inspection or testing; no experiment claimed here. |

Control tests should cover the legitimate task and both attack routes: approved reporting succeeds; unauthorized transfer requests fail whether refused by the agent or blocked by enforcement; a helper using synthetic records cannot complete the transfer; summarization, delegation, and retained memory cannot independently authorize the destination. Use synthetic records and controlled endpoints. Evidence should show both proposal and effect.

Reusable field definitions live in the [shared appendices](appendices.md). [Chapter 3](chapter-03-system-task-authority.md) through [Chapter 5](chapter-05-threats-controls-and-evidence.md) turn this vocabulary into the full review procedure.

## References

1. Xiangyu Qi et al. [Fine-tuning Aligned Language Models Compromises Safety, Even When Users Do Not Intend To!](https://arxiv.org/abs/2310.03693). 2023. Experimental evidence concerning customization and safety behavior.
2. Zhaorun Chen et al. [AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases](https://arxiv.org/html/2407.12784v1). July 17, 2024 version. Controlled attack research; cited for the mechanism and experimental conditions, not a production breach.
3. Yi Liu et al. [Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale](https://arxiv.org/html/2601.10338v1). January 15, 2026 preprint. See Section 4.5.2 for the code-review skill and the limitations discussion for interpretation of findings.
