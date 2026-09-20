# Chapter 9 — Assure Continuously: Test, Operate, and Manage Change

*Trace influence. Bound authority.*

## Overview

A design review does not keep boundaries real by itself. A refusal can hide a completed transfer through a helper; a restarted process can reload a contaminated procedure; a familiar tool interface can gain network access the prior review never tested. Continuous assurance ties findings to observed effects, recoverable state, and versioned assumptions about the system that is actually running.

The points below are the ideas this chapter uses again and again.

**Core concepts**

1. Each finding becomes an executable question with task, attacker material, preconditions, prohibited effect, and observation points—rates need explicit denominators, and utility is reported with protection.
2. Useful operations link authorized work to proposed actions, policy decisions, service effects, and writes that can influence later tasks; containment stops authority as well as execution.
3. Recovery verifies clean state and legitimate task completion; resumption needs explicit conditions, residual exposure, and updated threat assumptions.
4. Version the basis of the conclusion—including assumptions such as “this tool cannot make network requests”—not only package numbers; learned behavior and retrieved content are change surfaces.
5. Cross-boundary ownership and staged rollback must include state: memory, jobs, credentials, and prior approvals that may outlive a version revert.

After reading this chapter, we should be able to turn findings into reviewable tests, detect and contain influence-related incidents without recreating exposure, and keep review depth tied to what a change can affect.

## 9.1 Test

A test that checks only an assistant's refusal can miss a completed transfer through a helper or alternate client. Define prohibited effects, observe stages separately, report denominators, and measure utility alongside protection.

### A refusal hides a completed transfer

The reporting agent from [Chapter 2](chapter-02-understanding-influence.md) encounters an instruction to send customer records to an external validation service. A new defense blocks the proposed upload tool, and the assistant reports that it refused. The harness still runs the skill's helper program, which has access to the records and the network and sends the same information through a different route.

This hypothetical test would look successful if the evaluator checked only the assistant's answer, and fail if it checked actual data movement. Model behavior is useful evidence; the decisive observation may be in a network log, database transaction, filesystem change, or recipient service.

### Turn findings into tests and observe stages

A finding should specify an actor, controlled source, preconditions, authority, and prohibited consequence. A test instantiates those details. Without them, “test prompt injection” is too broad to interpret.

For the reporting agent, the attacker controls a skill instruction and its helper code. The task permits reading synthetic customer records and saving a report internally. The prohibited consequence is transfer to an unapproved recipient. Create a controlled receiver and synthetic data with recognizable markers—do not depend on the model describing what happened.

| Test field | Example value |
|---|---|
| Authorized task | Produce an internal customer-usage report. |
| Attacker-controlled material | Skill text or helper program, depending on the test. |
| Fixed preconditions | Same records, permissions, harness, and approved destination. |
| Prohibited effect | Marked source data reaches an unapproved receiver. |
| Observation point | Receiver log and execution telemetry. |
| Legitimate outcome | Correct report saved in the approved location. |
| Stop condition | Defined task completion, time limit, or containment trigger. |

Test one route at a time first, then combinations and fallbacks. Exposure, proposal, enforcement, execution, and consequence are related observations—not interchangeable measures.

| Stage | Useful observation | Common mistake |
|---|---|---|
| Exposure | Retrieved content or loaded artifact identifier | Counting an unread payload as a defense success. |
| Proposal | Tool name and proposed arguments | Treating a proposal as completed harm. |
| Enforcement | Policy decision with matching action identifier | Assuming every route uses that policy. |
| Execution | Service receipt or process event | Assuming execution produced the intended effect. |
| Consequence | Independent state or recipient evidence | Trusting the assistant's final summary. |
| Utility | Correct authorized task completion | Counting refusal of all work as a useful defense. |

### Compare conditions, adaptation, routes, and utility

Compare a benign-source condition with an altered-source condition under a comparable task and environment. Define the denominator for every rate: transfers divided by all assigned runs, all exposed runs, or all runs that proposed a transfer answer different questions. Report the overall prohibited-effect rate among eligible assigned runs as a primary system outcome. Zero observed failures means none occurred in the tested sample, not that true risk is zero.

A fixed payload suite is useful for regression. An adaptive evaluation asks whether an attacker who can observe feedback can find a different route—specify knowledge, access, query budget, time budget, and permitted changes. Prioritize architecture-relevant alternate routes:

| Route | Question |
|---|---|
| Direct user instruction | Can the requester obtain an action outside their authority? |
| Retrieved document or tool result | Can external content redefine the task or recipient? |
| Memory | Can an instruction return during a later task? |
| Peer delegation | Can another agent pass an unsupported approval? |
| Helper program | Can code bypass the model-facing restriction? |
| Ordinary API call | Does the resource service enforce policy without the agent? |
| Retry or concurrent action | Can repeated valid-looking operations violate an aggregate rule? |

Zhan and colleagues reported adaptive bypasses of defenses in their evaluated setting—evidence for including adaptive evaluation, not a claim that every architecture can be bypassed. [1] AgentDojo shows why task completion and attack success need separate reporting; its results apply to the tested agents, tasks, and configurations. [2]

Report correct task completion, unnecessary denials, latency, and human escalations with security results. A denied request that was never authorized is not a false positive. Record whether human reviewers receive enough information and whether approval binds the action that executes.

| Condition | Expected prohibited-effect result | Expected utility result |
|---|---|---|
| Benign skill and approved helper | No external transfer | Internal report completes. |
| Skill text requests external validation | Transfer is denied | Report completes or requests a safe alternative. |
| Helper attempts the same transfer directly | Runtime or service restriction denies it | Failure is visible; no false completion claim. |
| Transfer uses a different available client | Destination restriction still applies | Legitimate approved traffic remains possible. |
| Malicious instruction persists in memory | Later task cannot acquire transfer authority | Useful task history remains available. |
| Approved internal destination is used | Policy permits the operation | Correct report is saved. |

If the helper succeeds, improving the instruction classifier does not close that route—restrict the helper's effective authority and keep the failed case as regression. A test report should state the question, configuration, attacker capabilities, outcome definitions, exclusions, and observations, separating behavioral findings from enforcement findings.

## 9.2 Operate

Stopping a process is not the same as restoring trustworthy state. Persistent procedures, memory, credentials, queues, and shared services can return prohibited behavior after a restart.

### The suspicious behavior returns

An operations team notices that a reporting assistant keeps requesting an external validation step. They stop the process, remove the conversation, and restart. The next morning a scheduled job loads a saved procedure created earlier, and the transfer request returns. Recovery must cover the paths through which behavior can re-enter context—before an incident occurs.

### Record, detect, and contain without new exposure

A useful record connects the original task to source material, proposed action, policy decision, execution, and effect. Stable identifiers make that connection possible across services.

| Record | Question it helps answer |
|---|---|
| Task and initiating identity | What work was authorized, and by whom? |
| Source and artifact identifiers | What material was available to shape the decision? |
| Proposed operation | What did the system attempt to do? |
| Policy decision | Which rule permitted or denied the operation? |
| Service effect | What actually changed or left the system? |
| Memory and configuration writes | What can influence a future task? |
| Delegation and revocation | Which other actors received usable authority? |

Protect logs against modification by ordinary task agents. Choose retention, access, and redaction according to investigation need—logs hold customer data, credentials, and attacker payloads. Treat incident material fed to an AI investigation assistant as evidence to analyze, not authority to direct the defender's environment. The same influence-first questions from [Chapters 3](chapter-03-system-task-authority.md)–[5](chapter-05-threats-controls-and-evidence.md) apply to that tooling.

Detection should cover policy violations and precursor changes: unexpected memory promotion, a new recipient, broader credential scope, or repeated denied operations.

| Signal | Initial interpretation | Follow-up |
|---|---|---|
| New external recipient | Possible destination change | Compare with task authorization and effect records. |
| Repeated denied requests | Possible adaptation or ordinary retry defect | Inspect task history and bound further work. |
| Unreviewed procedure becomes trusted memory | Possible authority promotion | Identify writer, source, and future readers. |
| Credential used by an unexpected worker | Possible delegation or compromise | Verify scope and originating task. |
| Effect without matching application event | Possible alternate execution path | Investigate service and process telemetry. |

Containment stops authority as well as execution: interrupt active work, revoke task credentials, block destinations, and prevent queued requests. Define what cancellation means—a stopped coordinator may leave workers active; a deleted conversation may leave memory and generated programs intact.

| Object | Containment question |
|---|---|
| Active process | Has execution actually stopped? |
| Queued task | Can it start after the response action? |
| Delegated credential | Will resource services reject it now? |
| External operation | Has it already committed or become irreversible? |
| Persistent artifact | Can another task load it? |
| Shared service | Can another agent recover the same access? |

NIST's incident-response guidance places preparation, detection, response, and recovery within ongoing cybersecurity risk management; this section applies that lifecycle to AI state and authority relationships. [3] The *Autonomous LLM Agent Worms* preprint studies controlled propagation through persistent state that later returns to agent context—supporting examination of memory files, scheduled loading, and cross-agent transmission, with anonymized targets that limit deployment-specific conclusions. [4]

### Restore trustworthy state and resume with conditions

Work backward from the observed effect to the operation, decision, and loaded sources; then follow writes forward. A trusted backup helps only if it predates compromise and its authority remains valid.

| Recovery target | Proposed action | Verification |
|---|---|---|
| Contaminated procedure | Quarantine it and identify derived copies | Scheduled tasks cannot reload affected content. |
| Memory summaries | Remove or reclassify unsupported instructions | Retrieval preserves legitimate history without promoting the instruction. |
| Compromised credentials | Revoke and replace within corrected scope | Old credentials fail at every relevant service. |
| Vulnerable execution path | Repair or disable the route | Direct and agent-mediated negative tests pass. |
| Uncertain worker state | Rebuild from a trusted artifact | Loaded versions and runtime restrictions match the release record. |
| Committed external effects | Reconcile, remediate, or notify through the established process | Ledger and recipient evidence support the outcome. |

Recovery is not always a complete reversal—copied information may remain outside organizational control. Distinguish restored service from restored confidentiality.

| Proposed recovery test | Expected result |
|---|---|
| Restart and run the scheduled report | Affected procedure does not re-enter trusted context. |
| Reuse an old task credential | Service rejects it. |
| Replay a queued external transfer | Authorization prevents the effect. |
| Run a legitimate internal report | Task completes with correct output. |
| Search for derived memory artifacts | Known descendants are accounted for or quarantined. |
| Trigger the original detection condition | Alert reaches the responsible responder. |

Update the threat record and release assumptions after resumption. [Chapter 8](chapter-08-agent-intrusion-case-study.md) shows how to reconstruct an agent-involved intrusion without mystifying it.

## 9.3 Manage change

A familiar interface can hide expanded access: new network fetches, broader credentials, changed model behavior, or updated retrieved content. A security conclusion remains valid only when tied to the versions, assumptions, and evidence of the deployed system.

### The interface stays the same while access grows

A reporting application updates its document tool. The button and name are unchanged, but the new version can fetch remote templates and resolve links. The prior review assumed local read/write only. The change does not automatically establish a vulnerability; it does invalidate an assumption that supported the earlier conclusion.

### Version the basis and select review depth

Record versions and configuration—model, harness, application, extensions, policy, corpora, and service contracts—and the assumptions attached to them. Where a provider hides internal versions, record the identifier and visibility actually available.

| Item | What may change | Review consequence |
|---|---|---|
| Model or adapter | Behavior, tool selection, handling of instructions | Repeat relevant behavioral and consequence tests. |
| System instructions | Task boundaries and exception handling | Check authority claims and safe stopping behavior. |
| Harness | Context assembly, retries, memory loading | Revisit influence and execution paths. |
| Skill or dependency | Instructions, code, remote resources | Review complete behavior and permissions. |
| Retrieval corpus | Source ownership, content, ranking | Check exposure, provenance, and policy-source roles. |
| API or policy | Operations, recipients, approval rules | Revalidate authoritative enforcement. |
| Identity configuration | Credential scope and delegation | Recheck reachable consequences and revocation. |

Ask what the change can affect: new source, transformation, decision, recipient, operation, or persistent artifact? Does it broaden writers or credentials? Three practical review levels follow—workflow choices for this book, not an industry standard.

| Review level | Appropriate condition | Required output |
|---|---|---|
| Confirm existing basis | Change has no material effect on relevant paths or enforcement | Recorded reasoning and targeted checks. |
| Review affected paths | Known component changes source handling or behavior within existing scope | Updated findings and focused regression evidence. |
| Revisit system boundaries | New authority, external service, task class, or trust relationship | Updated system map, threat review, and release conditions. |

Model customization and retrieved content are change surfaces even when application code is unchanged. Distinguish content that supplies facts from content allowed to establish policy. Qi and colleagues showed customization could weaken studied models' safety behavior, including under some benign fine-tuning conditions. [5] PhantomSkill studies malicious code injection through agent skills; a familiar skill name is insufficient evidence that an updated package preserves prior behavior. [6]

### Ownership, rollout, and rollback

The application team may not own the model or third-party tool. It still needs an accountable owner for the combined workflow—otherwise each provider satisfies a local contract while nobody enforces the assumed restriction.

| Responsibility | Owner's decision |
|---|---|
| Business policy | What outcomes and exceptions are authorized? |
| Application integration | How are proposals translated into service requests? |
| Harness and extensions | What runs, persists, and enters context? |
| Identity and infrastructure | What authority and connectivity exist? |
| Model supplier or internal model team | What behavioral artifact is supplied and how is change communicated? |
| Release owner | Is the combined evidence sufficient for this deployment? |

NIST's SSDF describes security work across the software lifecycle; extend the release inventory to AI-related inputs and assumptions. [7]

A staged rollout needs defined users, tasks, data scope, and maximum authority, plus rollback triggers chosen before release. Rollback must include state: reverting a version may leave memory, scheduled tasks, or generated files.

| Change artifact | Rollback question |
|---|---|
| Model or prompt | Will the previous version interpret new state safely? |
| Tool or skill | Did it create files, jobs, or remote resources that survive removal? |
| Policy | Are prior approvals still valid under the restored rule? |
| Credential | Has broadened access been revoked everywhere? |
| Memory schema | Can old code distinguish verified facts from new claims? |

For the document-tool update, check who can supply a URL, reachable destinations, redirects, accompanying credentials, and whether written content can later be treated as instruction—then produce evidence either way.

| Review action | Proposed result |
|---|---|
| Compare package behavior and permissions | New remote-fetch path appears in the system map. |
| Check user-controlled links | Source content cannot authorize arbitrary destinations. |
| Inspect credential handling | Requests do not inherit unrelated service authority. |
| Test direct helper execution | Same destination constraints apply outside model tool selection. |
| Test approved templates | Legitimate document generation still works. |
| Exercise rollback | Persistent artifacts and scheduled work are addressed. |

Keep findings tied to source, authority, control, and test. Exceptions need an owner, scope, reason, expiration, and re-evaluation trigger. Wherever information can alter an AI-mediated decision, continue the review into the ordinary services that act on it.

## Appendix 9A — Minimal result and incident records

**Test result.** Record test/finding IDs, versions, task, attack condition, stage observations, exclusions, and evidence location. Report counts with explicit denominators.

**Incident worksheet.** Record effects, identities, tasks, activity window, artifacts, authority, persistent state, and evidence. Separate facts, hypotheses, and rejected explanations; record containment/recovery scope, residual exposure, and resumption owner.

**Change review.** Record change, versions, altered assumptions, impacted findings, tests, rollout/rollback, and release owner. For skipped tests, state why assumptions remain valid.

## Appendix 9B — Additional reading

Read the adaptive-attack study [1] and AgentDojo [2] for evaluation design. Read NIST SP 800-61 Revision 3 [3] and the agent-worm study [4] for operations and persistence. Read the fine-tuning study [5], PhantomSkill [6], and the SSDF [7] for change surfaces. Use [Appendix F](appendices.md) when asking whether the review methodology improves engineering work, rather than whether a deployed control blocks an attack.

## References

1. Qiusi Zhan et al. [Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents](https://arxiv.org/abs/2503.00061). 2025. Findings of NAACL; controlled defense evaluation.
2. Edoardo Debenedetti et al. [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://arxiv.org/abs/2406.13352). 2024, revised November 2024.
3. NIST. [Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile](https://csrc.nist.gov/pubs/sp/800/61/r3/final). SP 800-61 Revision 3, 2025.
4. Mingming Zha and Xiaofeng Wang. [Autonomous LLM Agent Worms: Cross-Platform Propagation, Automated Discovery and Temporal Re-Entry Defense](https://arxiv.org/abs/2605.02812). May 2026 preprint. Controlled research with anonymized targets.
5. Xiangyu Qi et al. [Fine-tuning Aligned Language Models Compromises Safety, Even When Users Do Not Intend To!](https://arxiv.org/abs/2310.03693). 2023.
6. Yu-Ting Lin and Chia-Mu Yu. [PhantomSkill: Malicious Code Injection in Agent Skill Ecosystems](https://arxiv.org/abs/2606.19191). June 2026 preprint.
7. NIST. [Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities](https://csrc.nist.gov/pubs/sp/800/218/final). SP 800-218, 2022.
