# Chapter 6 — Apply the Method Across AI System Layers

*Trace influence. Bound authority.*

## Overview

Chapters [3](chapter-03-system-task-authority.md)–[5](chapter-05-threats-controls-and-evidence.md) already define the review procedure: name the system and authority, map influence, then turn findings into controls and evidence. This chapter does not restate that method. It states only what changes when the same questions land on models, harnesses, extensions, applications, and multi-agent systems—different influence sources, different places authority must live, and different tests that can falsify the claim.

The points below are the layer deltas this chapter uses again and again.

**Core concepts**

1. **Models:** learned behavior from training and adaptation is a security-relevant change; evaluate against a deployment-specific contract and keep consequential enforcement outside model confidence.
2. **Harnesses:** context assembly, loops, memory promotion, and interruption can change a source’s status without changing the model.
3. **Skills, tools, and MCP:** an extension is both an instruction surface and software—inventory both routes, including identity and update paths.
4. **AI applications:** well-formed output can still drive unauthorized business transitions; validate meaning and state ownership, not only schema.
5. **Agent systems:** peer identity authenticates a sender, not content provenance or delegated scope; shared stores can bypass the messaging API.

After reading this chapter, we should be able to apply Chapters 3–5 at each layer by naming the extra sources, authority bounds, and tests that layer requires—without treating five domains as five separate methods. Complete end-to-end walkthroughs appear in [Chapters 7](chapter-07-complete-design-review.md)–[8](chapter-08-agent-intrusion-case-study.md); continuous assurance is in [Chapter 9](chapter-09-assure-continuously.md). Templates live in the [appendices](appendices.md).

## 6.1 Models

Model review must separate *behavior* from *authority*. The same artifact can be low impact in a drafting tool and high impact when connected to a payment executor; adaptation that improves tone can still teach unsafe procedures if training examples omit the approvals that made those procedures legitimate.

### What changes

**Sources.** Learned behavior comes from base training, fine-tuning or adapters, prompts and context, routing and fallbacks, and the consumers of output. For internal customization, record dataset provenance, selection criteria, transformations, and approval. Remove information unnecessary for the learning objective. Preserve distinctions between examples of advice and examples of authorized action—a transcript that says “refund approved” may be useful language data and an unsafe procedural example at once. The model cannot reliably infer a missing approval record from a transcript that never contains it.

A poisoning hypothesis still needs preconditions: can an actor insert enough relevant material, does training or retrieval select it, does a trigger survive preprocessing, and does the resulting behavior reach a consequential consumer? A suspicious example alone does not establish a deployed backdoor.

Two research results motivate reviewing what enters an artifact and what can come out. Qi and colleagues demonstrated safety degradation after customization, including adversarial fine-tuning and some benign-data conditions in their evaluated models—adaptation is a security-relevant change; the study does not establish every current model or training configuration. [1] Carlini and colleagues demonstrated extraction of memorized training data under studied conditions—evidence that generated output can reveal training-associated material, not that every record is searchable or retrievable. [2]

**Authority.** A model’s refusal behavior is relevant evidence, but it cannot establish the permissions of a connected service. Likewise, a strong access-control boundary does not establish answer accuracy. The review subjects below are what changes relative to a generic service inventory.

| Review subject | Security question |
|---|---|
| Base model | What behavior and limitations have been evaluated? |
| Adaptation | What changed through fine-tuning or an adapter? |
| Prompt and context | What instructions and information accompany inference? |
| Routing | Can requests move to another model or fallback path? |
| Output consumer | Which actions, displays, or stores use the result? |
| External enforcement | Which consequences remain blocked if behavior is unsafe? |

Hosted and self-managed deployments offer different evidence. The application team may see API behavior, selected versions, and provider documentation for hosted models, and artifact hashes, adaptation data, and runtime configuration for self-managed ones—each transfers different operational responsibility. Mixed routing requires preserving policy and data restrictions across fallbacks. Artifact integrity is necessary but limited: a verified hash matches the selected artifact; a signature identifies a publisher; neither establishes safe behavior. Keep recommendation roles, scoped inference data, and payment or policy enforcement outside the model’s behavioral assumption. Model replacement must preserve containment—a new tool-call format must not route arguments through a generic shell, and a fallback must not inherit broader credentials because its integration is easier to configure.

**Tests.** Evaluate against a behavioral contract that covers legitimate task quality, source-role preservation, uncertainty handling, unsafe-proposal detection, sensitive-output checks, and system enforcement that unsafe proposals cannot bypass. Prefer deployment-specific examples (refund policy, tenant boundaries, exception workflows) over generic refusal benchmarks alone; a narrow business test may still miss broader sensitive-data exposure. Keep a held-out set not used to select or tune the model; version inputs and scoring rules; review disputed outcomes with evidence rather than relying solely on another model’s judgment. Repeated runs reveal variation but do not create broad coverage by themselves. Define release gates—for example, no observed cross-tenant execution in a defined boundary set while accepting a bounded change in answer style—as deployment decisions, not universal safety proofs. High rates of blocked unsafe proposals can still create workload and pressure on other boundaries; rejecting the artifact may be warranted even when downstream controls hold.

### Example

A support team fine-tunes on successful conversations. Several examples contain exceptions granted by human operators without preserving the separate approvals that made those exceptions legitimate. The customized model treats similar exceptions as ordinary support behavior. If the payment service independently checks approval, the recommendation can be rejected; if the application treats model confidence as permission, a tone improvement changes financial behavior. The revised design separates ordinary responses from exception examples, evaluates against held-out boundary cases (customer-asserted exceptions, policy conflicts, prohibited destinations, fallback under failure, and legitimate eligible refunds), and keeps independent evidence requirements at the payment service. The review result names the artifact, configuration, evaluation set, observed limits, and permitted deployment scope—not only that the model “passed security.”

## 6.2 Harnesses

Ending a conversation is not always the end of an influence path. The harness—the software around the model that assembles context, runs loops, routes tools, and manages persistence—can promote a lower-trust observation into later guidance without changing model weights.

### What changes

**Sources.** Review actual responsibilities, not product labels. Framework terminology varies; the security questions below are what the harness layer adds to the influence map.

| Responsibility | Security question |
|---|---|
| Context assembly | Which sources are loaded, in what role, and with what attribution? |
| Planning loop | What limits repeated actions and defines a safe stopping point? |
| Tool routing | Which proposed operations reach which execution interfaces? |
| Memory management | What can be written, promoted, retrieved, or deleted? |
| Process execution | What files, credentials, and network paths can code access? |
| Observation | Which records distinguish proposals, denials, and effects? |
| Interruption | What actually stops after cancellation or revocation? |

Separate configuration from task data—system instructions and tool policies need controlled update paths; a task-generated file should not silently replace a startup instruction because both sit in the same directory. Memory is not one store. The state classes below need separate writing and promotion rules.

| State class | Permitted role | Example restriction |
|---|---|---|
| Task scratch | Temporary derived work | Not loaded as policy in unrelated tasks. |
| Conversation summary | Compact account of prior discussion | Preserve claims and unresolved status. |
| User preference | User-authorized convenience | Cannot override security or tenant policy. |
| Reusable procedure | Reviewed operational guidance | Promotion requires provenance and an authorized owner. |
| Security policy | Enforceable configuration | Task execution cannot edit its own limits. |

A summary should retain the distinction between “the page recommends an upload” and “uploads are approved.” Expiration is useful but insufficient—scope, provenance, ownership, and revocation matter alongside age. AgentPoison shows that malicious demonstrations in agent memory or retrieval stores can affect later behavior through retrieval without modifying weights—include memory writers and retrieval rules in the threat model; a clean current prompt does not establish freedom from earlier influence. [3]

**Authority.** Bound scripts and tools independently of context: filesystem, credentials, network destinations, and available tools must match the task. Friendly tool names do not establish safe behavior—a helper described as “format a report” may execute arbitrary commands or read environment variables. If a script can modify the allowlist, startup instructions, or audit configuration, its execution scope includes weakening future controls. Isolation claims must name shared caches and directories that can still carry cross-task influence. Loop limits must cover time, cost, steps, *and* consequential actions—a token cap alone does not bound external effects; one tool call can delete many records. When the task cannot complete with current permissions, support escalation or a clear incomplete result rather than silent expansion into a general shell. Retries need operation semantics: before repeating a consequential action, query status or use stable deduplication; a fresh request identifier on every retry defeats that protection.

Interruption semantics must define what cancellation, credential revocation, memory quarantine, and restart actually stop or reload. Cancellation before execution should prevent new consequential operations; cancellation during a long-running tool needs defined containment and recorded final status; quarantined memory must be excluded from future retrieval with affected descendants examined; restart should load only approved configuration and scoped retained state. Correlation identifiers help reconstruct tasks; knowing a task ID must not permit an unrelated actor to control it.

**Tests.** Check that external recommendations stay recorded as source content rather than policy; that compression preserves unverified status; that later retrieval creates no new transfer authority; that prohibited uploads remain blocked by runtime or data-service policy; and that quarantined guidance is not silently reloaded after restart—while approved in-scope diagnostics still work. The finding concerns promotion and execution, not merely whether memory contains suspicious words.

### Example

An operations assistant reads a troubleshooting page that recommends uploading diagnostics to an external service. It does not upload during the current task, but saves a procedure summary. A week later, retrieval presents that summary as established practice; the original uncertain source is gone. The revised harness stores the page recommendation as task evidence with its source, does not auto-promote it to an approved procedure, and separately prevents diagnostic data from reaching unapproved destinations—so a mistaken memory entry cannot create a data-sharing exception. Memory control reduces unsafe guidance; execution policy limits the consequence.

## 6.3 Skills, tools, and MCP

Extensions that look like small helpers can become full integrations: new code, remote fetches, credentials, and update paths under a familiar name. Review that stops at the visible instruction file misses executable behavior, mutable dependencies, and identity boundaries that determine impact.

### What changes

**Sources.** Inventory the package actually loaded. The elements below are what this layer adds beyond a prompt-only review.

| Element | Review question |
|---|---|
| Instructions | What decisions do they ask the agent to make? |
| Examples and references | Can they be promoted into policy or trigger execution? |
| Scripts | What files, processes, credentials, and network resources can they access? |
| Dependencies | Which versions are selected and who can publish replacements? |
| Remote content | Can it change after review or redirect to another source? |
| Installation hooks | What runs before the user invokes the visible feature? |
| Update mechanism | Who authorizes changes and what evidence is retained? |

A pinned top-level version may still fetch mutable resources; a reviewed instruction may call an unreviewed helper; a clean helper may install an unpinned dependency. Follow those relationships until executed behavior and update authority are clear. Origin and signatures establish integrity and publisher identity; they do not prove harmless code or task fit.

Instruction-mediated attacks and direct executable routes can coexist—one can prepare the other. Pair each route with its evidence and control location.

| Route | Evidence | Control location |
|---|---|---|
| Instruction changes a tool call | Context and proposed-call trace | Tool mediation and resource authorization |
| Helper directly reads secrets | Process and file-access evidence | Runtime isolation and secret access policy |
| Dependency runs during installation | Installation logs and package behavior | Build/install isolation and dependency controls |
| Remote reference changes later behavior | Versioned fetch records | Pinning, content review, and runtime restrictions |

A prompt classifier may miss ordinary-looking code with harmful side effects; a static scanner may miss a false approval instruction in text. Documented cases motivate two-route review without turning experimental rates into deployment risk estimates: *Agent Skills in the Wild* reports hidden instructions in skill instruction files (artifact-analysis patterns, not a verified victim count); [4] PhantomSkill studies malicious behavior in auxiliary resources disguised as ordinary-looking vulnerable code. [5] Scripts can be necessary; their behavior and authority must match the task.

**Authority.** Protocol names such as MCP do not decide safety. Record server identity, authentication flow, token audience and scope, tool contracts, returned content, and local process access. Keep human, client, server, and downstream service identities distinct—a server receiving a valid request may still lack authority for the downstream operation; a tool result may carry untrusted instructions alongside useful data. Official MCP security guidance addresses token passthrough, confused-deputy behavior, request forgery, and local server compromise; check deployed implementations against their actual protocol and configuration. [6] If the server runs locally, examine it as a process with filesystem and environment access, not merely as a remote API. Discovery shows what a server advertises—it does not establish that every user may invoke every operation.

Lifecycle stages—discover, install, activate, operate, update, revoke—are security decisions. Before installation, identify owner, intended function, required permissions, and update source; review in isolation with synthetic data and scoped credentials. At activation, grant only resources required by the approved task. During updates, compare behavior as well as version strings—new network access, hooks, tool arguments, or memory writes change the security argument. Removal must delete or disable entry points, revoke dedicated credentials, and examine scheduled tasks, retained memory, generated configuration, and remote connections; removing a directory may not undo effects already created.

**Tests.** Deny unrelated credential reads; reject unapproved template redirects; ensure skill text requesting a raw-data upload produces no prohibited transfer; detect expanded execution when a new version adds an installation hook; after revocation, block new invocations and retained scheduled work under old authority—while the approved formatting (or other intended) task still succeeds. The acceptance record should identify reviewed package and resource versions. If remote content remains mutable by design, name the runtime controls that limit its effects; do not label a review permanent when covered behavior can change independently.

### Example

A formatting skill’s update adds a remote template service and a helper that collects diagnostics on failure. The name and user-facing task stay “format this report,” but behavior now includes outbound requests and possible environment-variable access. The revised design gives the helper only the draft and a designated output directory, obtains templates through an approved fetch path with bounded destinations, and reviews diagnostics under separate explicit policy—no general credential environment.

## 6.4 AI applications

Well-formed model output can still produce unauthorized business effects when the application treats a source claim as an authoritative state transition. Schema validation and fluent extraction do not decide who may establish a payment destination, an approval, or a completed transaction.

### What changes

**Sources.** Ambiguous words such as “approved” may mean a customer claim, an assistant recommendation, a manager decision, or an executor acceptance—different states with different owners. Retrieval-augmented generation adds corpus writers, access filters, ranking, extraction, and freshness to the review. Separate policy sources from customer-supplied evidence; relevance is not authority. Enforce tenant and resource access with trusted request context *before* protected material reaches the model—filtering only the final answer leaves the model and other consumers exposed. The model should not construct security filters from untrusted text; a tenant identifier in a document is data to check, not a replacement for authenticated context.

| Retrieval concern | Application requirement |
|---|---|
| Corpus ownership | Only designated publishers can promote policy documents. |
| Tenant access | Retrieval respects the current actor's entitlement. |
| Freshness | Policy versions and effective dates are available. |
| Source role | Customer evidence remains distinct from policy and approval. |
| Citation | A citation identifies supporting material without implying independent verification. |
| Failure | Missing authoritative evidence leads to escalation or a bounded answer. |

Recommendations can influence people and downstream systems without a tool call—output role and evidence labeling are part of the specification. Distinguish extracted facts, source claims, unresolved discrepancies, and authoritative decisions; avoid presenting confidence as verification. A draft for expert review can permit more uncertainty than a customer-facing statement of completed payment. Fides studies agent execution under confidentiality and integrity policies and supports considering source integrity and disclosure constraints together under its stated assumptions; business semantics (who may change a bank account, which approval covers which fields) still require application-specific policy. [7]

**Authority.** Define business states and owners explicitly before implementing prompts. Descriptive model text must not be the sole state record.

| State | Meaning | Who can establish it? |
|---|---|---|
| Received | A document or request arrived. | Intake service |
| Validated | Required fields and authoritative relationships have been checked. | Application services |
| Recommended | A proposed action is ready for consideration. | Assistant or business logic |
| Approved | An authorized decision covers exact transaction fields. | Approval service |
| Executed | The operation actually completed. | Payment service |
| Reconciled | Records agree with the external effect. | Reconciliation process |

Prefer identifiers resolved by authoritative services over copying sensitive fields through natural language. New destinations need dedicated verification workflows; reusing ordinary invoice approval for a supplier-account change creates an authority mismatch. Output consumers need their own handling—safe rendering in browsers, separation of data from executable query structure, and no unrestricted generated shell commands merely because preceding JSON parsed. Concurrency, retries, and mid-workflow entitlement changes remain ordinary application-security concerns that AI planning can make more frequent: two agents each observing a refundable balance of 100 and requesting 80 can exceed the limit unless the state owner enforces aggregates atomically; use stable operation identity and status resolution before repeating uncertain effects; revalidate when requests or policy versions change after approval; apply documented execution-time authorization when entitlement is lost while queued.

**Tests.** Crafted invoices must not redirect execution when the executor resolves destinations from supplier state; text alone must not create approval records; concurrent workers must not exceed permitted aggregates; repeated timeout retries must produce one intended effect; human-facing UI must let reviewers see what still requires verification—while valid invoices complete without unnecessary escalation and legitimate bank changes succeed only through the designated workflow. Test results should identify actual effects and state transitions, not only the assistant’s explanation.

### Example

An invoice assistant correctly extracts supplier name, amount, and account number into valid structured output that cites the uploaded invoice. The invoice requests a new payment destination; the supplier registry holds a different approved account. Accepting the extract as current supplier information assigns the source a role it does not have. The redesigned assistant flags the discrepancy as a claim, proposes payment against the verified supplier record when policy permits, and routes destination changes through their own approval workflow. The model helps interpret evidence without becoming the source of permission.

## 6.5 Agent systems

Multi-agent collaboration creates new identities, message paths, shared state, and delegation relationships. An authenticated peer request can still be unauthorized when an untrusted source shaped the request, or when the receiver treats peer identity as sufficient approval for broader access.

### What changes

**Sources.** Roles such as researcher, planner, reviewer, and executor describe intended capability; permissions and enforcement define what each can actually do. Some deployments combine roles in one process—the same questions still apply: where is role separation enforced, and where is it only a prompt convention?

| Role | Intended capability | Boundary to preserve |
|---|---|---|
| Researcher | Gather permitted external evidence | Cannot authorize internal data access. |
| Planner | Propose task decomposition | Cannot grant privileges it does not possess. |
| Reviewer | Evaluate evidence or proposed work | Review output does not automatically become execution approval. |
| Executor | Perform scoped operations | Must validate the task and authority behind each request. |
| Coordinator | Assign work and collect status | Delegation cannot exceed its authorized scope. |

Authenticated messages remain carriers of claims—sender identity is not content provenance. An agent can forward material from an untrusted page, summarize inaccurately, or omit attribution; each handoff can make an unsupported statement appear more authoritative. Agents may share sources, model behavior, or missing context, so peer agreement is not proof. Shared files, caches, package services, queues, logs, and memory can transmit influence outside the intended messaging API; a shared cache must not allow one agent to replace another task’s executable artifact or trusted instruction. Conflicting actions require coordination at the state owner—spending limits and publication state should not depend solely on agents agreeing informally.

Prompt Infection studies malicious prompts propagating through interconnected agents; [8] the *Autonomous LLM Agent Worms* preprint reports controlled propagation involving persistent artifacts and later re-entry—review messages *and* stored state. [9] Both remain experimental evidence with stated conditions; they motivate mechanisms to examine rather than proving collaboration is inherently unsafe.

**Authority.** Delegated requests should carry more than prose—fields authoritative services can verify.

| Delegation field | Purpose |
|---|---|
| Originating task | Connect work to the authorized objective. |
| Requester and delegate | Identify the principals involved. |
| Resource scope | Bound which records or systems may be accessed. |
| Operation scope | Bound what may be done with those resources. |
| Validity and revocation | Limit how long the request remains usable. |
| Approval reference | Connect exceptional actions to authoritative decisions. |
| Provenance | Preserve the sources behind claims and recommendations. |

A child task cannot gain authority beyond what the parent may delegate; resource, operation, time, and budget scope may be narrowed; expansion needs an independent authorization path. Do not let an agent create authority by filling an “approved” field—message metadata from an untrusted sender remains a claim. Human workflows may intentionally authorize broader access at a later stage; that escalation must be part of policy, not arise solely because a peer message sounds persuasive.

Containment and revocation must cover workers, credentials, queues, and retained authority-bearing records—not only a stopped coordinator. A coordinator failure may stop scheduling while existing workers continue; revocation must address active tasks and delegated credentials. Separate proposal, review, approval, and execution records; bind final decisions to the operation that will execute. Issue short-lived, scoped access where practical rather than sharing broad long-lived credentials. Monitoring should correlate messages, delegations, policy decisions, and effects—a chain of summaries is not enough to reconstruct who had authority at execution.

**Tests.** Deny internal-export requests outside originating-task scope; require matching approval-service records when a message claims managerial approval; treat missing provenance as unable to create broader permission; keep onward delegation bounded or narrowed; fail new child operations when the parent task is revoked; enforce resource-level constraints when two executors act simultaneously. Collaboration remains possible because trust is specific rather than unconditional.

### Example

A research agent with only public-source access sends an execution agent a confident summary: obtain an internal customer export and attach it to the report—after a public page asserted that a complete report requires that export. Authentication of the peer succeeds; authorization may still fail. The revised design has the executor check the originating task (public-source report only), reject or escalate the export request, and allow the researcher to report that an external page requested additional data without converting that request into entitlement.

## Layer checklist

Use this list when choosing which layer deltas to emphasize. Fill the corresponding templates in the [appendices](appendices.md); do not treat a checked label as a completed review.

- **System and authority (all layers):** [Appendix A.1–A.2](appendices.md)—components, principals, source roles, effective authority, consumers, enforcement.
- **Threats and controls (all layers):** [Appendix A.3](appendices.md) and [B.1](appendices.md)—findings with preconditions and mechanisms; falsifiable control contracts at enforcement points.
- **Models:** artifact identity, adaptation lineage, behavioral-contract evaluation versions, routing/fallback, downstream enforcement ([Appendix A](appendices.md); release/change handoff in [B.3](appendices.md)).
- **Harnesses:** context sources, memory classes and promotion, tool routes, retry and cancellation semantics, restart/fallback state ([Appendix A.2](appendices.md); operations in [B.3](appendices.md)).
- **Skills, tools, MCP:** package inventory, instruction vs executable routes, token audience/scopes, install/update/revoke decisions ([Appendix A](appendices.md); validation in [B.2](appendices.md)).
- **AI applications:** business-action meanings and owners, RAG corpus and source-role rules, meaning validation beyond schema, concurrency/retry identity ([Appendix A–B](appendices.md)).
- **Agent systems:** role-by-authority boundaries, delegation fields, shared-store writers/readers, revocation propagation ([Appendix A.2](appendices.md)).
- **Assurance after the layer review:** tests and residual risk ([Appendix B.2](appendices.md); [Chapter 9](chapter-09-assure-continuously.md)); observe, contain, recover, and re-review on change ([B.3](appendices.md)).

Next: [Chapter 7 — Complete Design Review](chapter-07-complete-design-review.md) applies the full procedure end to end. For evidence categories when citing research cases, see [Appendix E](appendices.md).

## References

1. Xiangyu Qi et al. [Fine-tuning Aligned Language Models Compromises Safety, Even When Users Do Not Intend To!](https://arxiv.org/abs/2310.03693). 2023.
2. Nicholas Carlini et al. [Extracting Training Data from Large Language Models](https://arxiv.org/abs/2012.07805). Research demonstration of training-data extraction.
3. Zhaorun Chen et al. [AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases](https://arxiv.org/abs/2407.12784). 2024.
4. Yi Liu et al. [Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale](https://arxiv.org/abs/2601.10338). January 2026 preprint.
5. Yu-Ting Lin and Chia-Mu Yu. [PhantomSkill: Malicious Code Injection in Agent Skill Ecosystems](https://arxiv.org/abs/2606.19191). June 2026 preprint.
6. Model Context Protocol. [Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices). Versioned documentation consulted September 2026.
7. Manuel Costa et al. [Securing AI Agents with Information-Flow Control](https://arxiv.org/abs/2505.23643). Fides, 2025.
8. Donghyun Lee and Mo Tiwari. [Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems](https://arxiv.org/abs/2410.07283). 2024 preprint.
9. Mingming Zha and Xiaofeng Wang. [Autonomous LLM Agent Worms: Cross-Platform Propagation, Automated Discovery and Temporal Re-Entry Defense](https://arxiv.org/abs/2605.02812). May 2026 preprint.
