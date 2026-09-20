# Shared Appendices — Influence-First AI Security

*Condensed edition: templates and definitions for the nine-chapter book.*

These templates consolidate the working records used throughout the book. Use the fields that matter to the system under review, and preserve the links between policy, findings, controls, and evidence. A completed table is useful only when its statements can be checked.

## Appendix A — Review templates

The templates below capture system description, authority and influence mapping, and threat records so later controls and tests stay tied to the same facts.

### A.1 System description

A system description should be specific enough that another reviewer can identify what is included. Record deployment differences where they change authority or connectivity.

| Field | Record |
|---|---|
| Review identity | System, deployment, owner, date, and reviewed versions. |
| Business task | Authorized users, intended work, and permitted outcomes. |
| Unacceptable consequences | Information exposure, unauthorized change, disruption, and other material harm. |
| Components | Models, harnesses, application services, extensions, and agents. |
| External dependencies | Providers, remote resources, and visibility limits. |
| State | Databases, files, caches, memory, queues, and scheduled work. |
| Assumptions | Facts the security conclusion depends on, with evidence and owners. |

See [Chapter 3](chapter-03-system-task-authority.md).

### A.2 Authority and influence map

Map both model-mediated influence and direct executable routes. They may share an outcome while requiring different controls.

| Field | Record |
|---|---|
| Principal | Human, service, agent, or external source. |
| Source role | What the source may legitimately establish or affect. |
| Effective authority | Operations, resources, recipients, time, and delegation scope. |
| Transformations | Retrieval, extraction, summary, memory, or handoff. |
| Decision | Interpretation or selection affected by the source. |
| Consumer | Service, person, database, or agent that uses the result. |
| Enforcement | Component that verifies the relevant policy. |
| Persistence | What survives and when it can return to context or execution. |

See [Chapter 4](chapter-04-mapping-influence.md).

### A.3 Threat record

Record one materially distinct failure per finding. Include the actor or failure source, preconditions, source control, mechanism, authority, consequence, existing enforcement, evidence status, owner, and priority rationale.

Keep consequence severity separate from confidence that the path is feasible. Record duplicates and blocked paths with reasons. See [Chapter 5](chapter-05-threats-controls-and-evidence.md).

## Appendix B — Control and validation templates

Control and validation records make policy promises falsifiable and keep operational handoffs explicit.

### B.1 Control contract

A control statement should make a falsifiable promise within its scope. “Use guardrails” is not enough to establish what an engineer must implement.

| Field | Record |
|---|---|
| Policy | The exact operation or consequence that is permitted or prohibited. |
| Enforcement point | Where the decision is checked independently of unsupported claims. |
| Inputs | Identity, resource, approval, provenance, and state required for the check. |
| Coverage | APIs, helper programs, retries, delegated calls, and other relevant routes. |
| Failure behavior | What happens when evidence or a dependency is unavailable. |
| Owner | Team responsible for implementation and operation. |
| Residual risk | Remaining exposure, assumptions, and acceptance conditions. |

See [Chapter 5](chapter-05-threats-controls-and-evidence.md).

### B.2 Validation record

Record the finding identifier, system versions, authorized task, attack condition, expected prohibited effect, observation point, legitimate outcome, exclusions, and actual result. Preserve exposure, proposal, enforcement, execution, and consequence observations separately.

Report counts and denominators. A refused answer is not evidence that a helper did not act. See [Chapter 9](chapter-09-assure-continuously.md).

### B.3 Operational and change handoff

Record monitoring coverage, containment actions, revocation scope, persistent-state cleanup, rollback procedure, release conditions, and responsible owners. Identify which changes require renewed review.

Use [Chapter 9](chapter-09-assure-continuously.md) for recovery, change management, and continuous assurance.

## Appendix C — Terminology and notation

The terms below are used with the meanings given in this book. An arrow in an influence map indicates a relevant flow or dependency. It does not by itself prove causal influence or exploitability. Mark candidate paths, demonstrated paths, and verified blocking controls distinctly.

| Term | Meaning in this book |
|---|---|
| Influence | Capacity of information, instructions, or learned behavior to shape interpretation, decision, or action. |
| Influence-first | Explicit, consistent attention to influence within whole-system threat modeling. |
| Authority | The legitimate scope to establish a decision or perform an operation. |
| Configured permission | Access the technical system currently permits; it may exceed human-authorized scope. |
| Source role | The facts, requests, or instructions a source may legitimately contribute. |
| Provenance | Evidence about origin and transformation; origin alone does not establish truth or authority. |
| Trust boundary | A point at which assumptions, authority, or required validation change. |
| Harness | The software that assembles context, manages execution, invokes tools, and often handles persistence. |
| Guardrail | A specified preventive, detective, or limiting control; name its actual mechanism. |
| Actionable finding | A substantiated issue specific enough to support remediation or a verification decision. |

“First” does not impose a fixed review order or rank influence above every other risk. See [Chapter 1](chapter-01-influence-first-security.md) and [Chapter 2](chapter-02-understanding-influence.md).

## Appendix D — Framework cross-references

These are complementary contributions rather than interchangeable scoring systems. The table below connects familiar frameworks to influence-first questions without treating any catalog as a complete system review.

| Framework or concept | Contribution | Influence-first connection |
|---|---|---|
| CIA | Identify confidentiality, integrity, and availability objectives | State the consequence of a decision or action. |
| STRIDE | Systematic threat-identification questions | Ask additional source-role and decision questions within the review. |
| Least privilege | Limit available authority | Bound consequences when interpretation is unsafe. |
| Complete mediation | Check relevant access and operations | Cover alternate APIs, helpers, and delegated routes. |
| Information-flow analysis | Examine propagation and restrictions | Trace information through interpretation and downstream consumption. |
| ATT&CK | Organize observed adversary behavior | Describe mechanisms without treating the catalog as a complete system review. |
| CVE and advisories | Identify specific published vulnerabilities | Keep vulnerability identity separate from authorization and incident attribution. |
| CVSS | Characterize vulnerability severity under defined assumptions | Contribute to risk analysis without replacing business context or evidence. |

Consult the primary foundations discussion in [Chapter 1](chapter-01-influence-first-security.md).

## Appendix E — Case-study evidence guide

Separate attempted action, demonstrated capability, and confirmed effect. Use firsthand reports for incident facts while retaining the limits and interests of involved parties. Independent sources also have scope limits.

### E.1 Identify the evidence type

Each evidence type below can establish different claims; none should be treated as interchangeable with the others.

| Type | What it can establish |
|---|---|
| Hypothetical example | Explain a plausible path and proposed controls; no observed prevalence. |
| Controlled demonstration | Establish outcomes under stated experimental conditions. |
| Artifact analysis | Establish properties found in sampled content, subject to the analysis method. |
| Production incident | Establish reported real-world actions and effects within the available evidence. |
| Proposed study | Define how a claim will be tested; no experimental result yet. |

### E.2 Vulnerability and discovery record

Record the specific flaw, affected component, event date, public-disclosure date, CVE if verified, discovery attribution, remediation evidence, and uncertainty. A familiar technique can exploit a previously unknown implementation flaw.

“No public mapping verified” is not evidence of a pending CVE request. A valid credential does not establish the actor's authorization. See [Chapter 8](chapter-08-agent-intrusion-case-study.md).

## Appendix F — Research and evaluation protocol

This appendix is a **proposed comparative study**. It reports no newly conducted experiment. Finding the same weakness does not prove two reviews are equally useful: control quality, actionability, and verified enforcement differ. Influence-first may help discovery, explanation, control design, or communication—benefits that must be tested separately.

### F.1 Chain of claims

Established security principles apply to the whole system, and research and incidents show that information can shape AI-mediated behavior. That supports making influence and authority explicit. It does not prove that this book's particular procedure improves a review. Comparative benefit is an empirical question.

The claim levels below separate what the book supports from what remains open to measurement.

| Claim level | What would justify it | Position of this book |
|---|---|---|
| Relevant mechanisms exist | Documented attacks and controlled demonstrations | Supported within the conditions of the cited evidence. |
| Explicit influence analysis is coherent | Clear definitions and findings connected to ordinary security concepts | The book supplies this reasoning and worked examples. |
| The procedure is usable | Reviewers can apply it consistently with reasonable effort | A practical proposal requiring user studies. |
| It improves review outcomes | Fair comparison with a competent alternative | Unestablished by the cases in this book. |
| It improves deployed security | Better implemented controls and measured outcomes over time | Requires additional engineering and longitudinal evidence. |
| It is universally superior or complete | Broad evidence across systems and failure classes | Not claimed. |
| It introduces a new security principle | A defensible novelty argument beyond terminology | Not claimed or required. |

A method can be useful without being novel, improve communication without finding more threats, and work in one domain without generalizing. Influence-first is a research-informed analysis proposal; its comparative effectiveness remains open to measurement.

### F.2 Study design essentials

A study cannot evaluate a slogan. It needs a versioned procedure participants can follow: define task and authority, identify sources and roles, trace transformations into decisions, follow downstream authority and effects, and produce findings with controls and tests—alongside whole-system threat modeling. Publish training materials and templates; state training time and permitted assistance. Unusually extensive coaching belongs in the result.

A reasonable comparator is competent STRIDE-based review with current AI security guidance. Give both groups the same architecture, source facts, code visibility, threat intelligence, time allowance, and output requirements. If reviews use AI assistance, give both groups equivalent access or study that factor separately.

**Primary question (first study):** does the added procedure increase the number of distinct, valid, actionable findings per review under a fixed time budget?

An actionable finding should identify a relevant consequence, a feasible path or substantiated design defect, the failed or missing boundary, and enough specificity to support remediation or verification. Control quality is a separate outcome: enforcement location, alternative-route coverage, and whether a proposed test observes the relevant effect.

Use more than one architecture (RAG, tool-using agent, persistent harness, multi-agent where feasible), plus ordinary authorization, injection, and transaction weaknesses. Include seeded flaws and realistic designs without exhaustive answer keys, and cases where a candidate path is blocked by a genuine control. Avoid constructing every system to match the book's examples. Define the unit of analysis before assignment: a team review is not an individual review. Prefer a parallel-group design when carryover from learning the method would bias a crossover.

### F.3 Outcomes and adjudication

The outcomes below need operational definitions before data collection begins.

| Outcome | Operational definition |
|---|---|
| Primary actionable finding count | Distinct findings meeting the predefined validity and actionability rubric within the time limit. |
| Finding precision | Accepted valid findings divided by all submitted findings; report adjudication uncertainty. |
| Known-threat coverage | Identified items divided by the eligible reference set, with limits on that set stated. |
| Control quality | Blinded rubric for policy fit, enforcement location, route coverage, and testability. |
| Effort | Preparation, review, documentation, and adjudication time recorded separately. |
| Ordinary-threat coverage | Performance on non-AI paths that remain in scope. |
| Practical usability | Training burden, completion, errors, and participant feedback. |

Do not call coverage of a reference set “all threats found.” Natural systems rarely have complete ground truth.

Use at least two independent assessors where practical. Hide the assigned method and remove method-specific headings when possible without altering substance; report blinding limits. Separate validity, distinctness, and actionability. Record disagreements before reconciliation. The rubric must not require the phrase “influence-first.”

| Rubric dimension | Strong evidence | Weak evidence |
|---|---|---|
| Policy connection | States the prohibited outcome and relevant authority | Calls behavior suspicious without identifying a rule. |
| Feasibility | Preconditions match the supplied system | Assumes missing credentials or nonexistent connectivity. |
| Boundary | Identifies where unauthorized influence or execution becomes possible | Names only the model or an attack category. |
| Remediation | Specifies an owner and enforceable restriction | Requests general awareness or stronger wording alone. |
| Validation | Tests actual effects and legitimate behavior | Checks only the final assistant response. |

### F.4 Interpretation and adoption

Choose a smallest practically meaningful improvement before collecting main data. Account for participants, teams, and systems when estimating uncertainty. Report effect estimates and intervals; keep exploratory analyses labeled as exploratory. Failure to detect a difference is not proof of equivalence.

| Observed pattern | Defensible interpretation | Practical response |
|---|---|---|
| More valid actionable findings, acceptable cost | Supports benefit for the studied setting | Replicate and test transfer to other teams. |
| Same findings, stronger control specifications | Supports a narrower control-design benefit | Reposition the method around that demonstrated value. |
| More findings, many invalid or duplicated | Quantity increased without clear useful gain | Simplify prompts and improve validity checks. |
| AI findings improve, ordinary threats are missed | Attention may have shifted at a security cost | Repair integration with whole-system review. |
| No meaningful advantage with sufficiently precise evidence | Added procedure may not justify its cost there | Use the simpler effective workflow. |
| Wide uncertainty | Study is inconclusive | Improve design or gather more evidence. |

A negative result is useful if it narrows the method's role. Terminology is not an outcome worth preserving against the evidence. A local pilot can inform adoption without justifying a universal effectiveness claim. For simpler systems, key questions may fit an existing threat template; for persistent memory, several agents, or complex transformations, a dedicated influence map may be worth the effort.

The customer-service agent in [Chapter 7](chapter-07-complete-design-review.md) illustrates the adjudication problem: two reviewers can find the same approval weakness while recommending a stronger prompt versus a service-level check with route coverage. Count threats for a tie; count implemented controls that prevent unauthorized payments for a more useful question. A follow-on engineering study of implemented controls is a separate question from review-output quality.

### F.5 Protocol checklist

Before recruitment, freeze the decisions below.

| Protocol field | Required decision |
|---|---|
| Research question | Primary comparative claim and target population. |
| Intervention | Versioned influence-first procedure and training materials. |
| Comparator | Competent whole-system review with equivalent AI guidance. |
| Systems | Selection rationale, seeded flaws, blocked paths, and realistic unknowns. |
| Allocation | Randomization, team structure, and carryover management. |
| Budget | Equal review resources; separate accounting for training. |
| Outcomes | Primary metric, secondary metrics, denominators, and deduplication. |
| Adjudication | Blinding, assessors, rubric, disagreement handling. |
| Analysis | Meaningful effect, sample planning, grouping, uncertainty, and exclusions. |
| Reporting | Negative results, deviations, limitations, and shareable materials. |

Obtain appropriate participant consent and protect proprietary system material. A completed report states what was tested, who participated, how allocation worked, what each group received, what was measured, and what happened—including uncertainty, departures, adverse tradeoffs, and generalization limits. Recruitment, experiments, statistical results, and replication remain future research; they are not implied completed work.

Prior empirical work shows threat-modeling methods can be studied and that adding structure does not automatically improve outcomes. Scandariato, Wuyts, and Joosen evaluated Microsoft's threat modeling with students [1]. Mbaka and Tuma examined threat validation with practitioners and found that added diagrams and LLM support did not establish an effectiveness advantage in the tested comparisons [2]. Those studies motivate evaluation of influence-first; they do not validate it.

### References

1. Riccardo Scandariato, Kim Wuyts, and Wouter Joosen. [A descriptive study of Microsoft's threat modeling technique](https://link.springer.com/article/10.1007/s00766-013-0195-2). Requirements Engineering, 2015; published online in 2013.
2. Winnie Bahati Mbaka and Katja Tuma. [Less is more: usefulness of data flow diagrams and large language models for security threat validation](https://link.springer.com/article/10.1007/s10664-026-10837-z). Empirical Software Engineering 31, article 122. April 21, 2026.

## Reference navigation

These appendices contain the book's proposed templates and definitions. Supporting external research and standards are linked in the numbered reference sections of the chapters cited above, and in Appendix F for the evaluation protocol.
