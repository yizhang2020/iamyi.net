---
title: "1. GenAI Application Taxonomy and Architecture"
keywords:
  - GenAI
  - architecture
  - RAG
  - agents
  - taxonomy
description: >
  Types of GenAI application architectures—RAG, agentic systems, MCP-style context,
  fine-tuned services, and hybrids—and how each shapes the attack surface.
date: 2026-05-01
---

# 1. GenAI Application Taxonomy and Architecture

## Purpose of this chapter

Before analyzing attacks or controls, it is essential to understand the types of GenAI applications and their structure. In GenAI systems, security failures typically arise from **architectural patterns** rather than isolated vulnerabilities.

This chapter classifies common GenAI application architectures and explains their core components, execution logic, and security-relevant characteristics. These patterns provide the foundation for threat modeling, lifecycle analysis, and control design in later chapters.

## Taxonomy matters for security

In traditional application security, similar architectures often imply similar threat models. In GenAI systems, this assumption **no longer holds**. Two applications may both “use an LLM,” yet have radically different attack surfaces depending on:

- How context is constructed
- Whether external data is retrieved
- Whether tools or agents can act autonomously
- Whether models are static or continuously updated

A clear taxonomy allows security teams to:

- Identify where influence enters the system
- Map trust boundaries accurately
- Avoid misapplying controls designed for the wrong architecture

## Core GenAI application types

### Overview of GenAI architecture patterns

GenAI applications can be grouped into a small number of recurring architectural patterns. Each pattern defines how inputs are transformed into model context, how decisions are made, and where external systems are involved.

The following subsections introduce the most common GenAI application types seen in production environments. For each type, the focus is on:

- Structural components
- Execution flow
- Security-relevant characteristics that shape the attack surface

This classification is intentionally **architectural** rather than vendor-specific, making it applicable across platforms and implementations.

### 1. Retrieval-Augmented Generation (RAG)

RAG applications combine an LLM with external knowledge sources, typically via embeddings and vector search. The model’s output is influenced not only by the user prompt but also by retrieved content.

**Key characteristics:**

- Dynamic context assembly
- External data as part of inference
- Separation between knowledge storage and model weights

**Security implication:** retrieved data becomes an **indirect control channel**.

### 2. Agentic / tool-using GenAI applications

Agentic systems extend GenAI beyond text generation. The model can plan, decide, and invoke tools or APIs to perform actions in external systems.

**Key characteristics:**

- Planning and reasoning loops
- Tool registries and execution environments
- Persistent or semi-persistent memory

**Security implication:** language-driven decisions can trigger **real-world side effects**.

A typical single AI agent system is often illustrated with a high-level diagram (place image files next to this page under `assets/`):

![Top agentic AI design patterns for architecting AI systems](../assets/image-20251231-142120.png)

*Caption (source notes in original material): “Top Agentic AI Design Patterns for Architecting AI Systems.”*

Inside an agent, components often include planners, tools, memory, and execution hooks—exact layout varies by framework.

### 3. MCP-style context-orchestrated applications

Model Context Protocol (MCP)–style systems focus on **structured context management**. Rather than a single prompt, context is assembled from multiple sources—files, APIs, tools, or memory—under explicit orchestration rules.

**Key characteristics:**

- Explicit context providers
- Separation of context assembly from inference
- Fine-grained control over what the model “sees”

**Security implication:** context orchestration logic becomes a **security boundary**.

**Diagram references (conceptual):**

- Inspired by Model Context Protocol (MCP) specifications and community designs
- Inspired by Anthropic and OpenAI context management patterns

### 4. Fine-tuned or custom-trained LLM services

In this model, organizations modify a base model through fine-tuning or custom training to embed domain-specific behavior.

**Key characteristics:**

- Training pipelines and datasets
- Model registries and versioning
- Separation between base model and tuned artifacts

**Security implication:** training data and pipelines become part of the **attack surface**.

![Training and deployment architecture (illustrative)](../assets/image-20251230-024922.png)

**Diagram references:**

- [Hugging Face — training and deployment documentation](https://huggingface.co/docs)
- [ThalesGroup/secure-ml (GitHub)](https://github.com/ThalesGroup/secure-ml) — secure ML framework (requirements, guidelines, tools, and privacy notes for ML applications)

### 5. Hybrid GenAI + traditional applications

Most real-world systems combine GenAI components with existing microservices, workflows, and business logic.

**Key characteristics:**

- Traditional APIs alongside LLM inference
- Mixed deterministic and probabilistic logic
- GenAI outputs feeding downstream systems

**Security implication:** **implicit trust** in model output can break existing security assumptions.

*Example: LLM assistant chatbot architecture.*

![Hybrid / chatbot architecture (illustrative)](../assets/image-20251230-030354.png)

**Diagram references:**

- Enterprise GenAI integration patterns (e.g. AWS, Azure)
- [AI architecture design — Azure Architecture Center](https://learn.microsoft.com/azure/architecture/)

## Architectural comparison summary

| Architecture type | Primary risk driver |
| --- | --- |
| RAG | Data as indirect instruction |
| Agentic AI | Language-driven action execution |
| MCP-style systems | Context assembly logic |
| Fine-tuned models | Training data integrity |
| Hybrid systems | Over-trust in probabilistic output |

Understanding which pattern applies is a prerequisite for accurate threat modeling. Misclassifying an application often leads to misplaced controls and false confidence.

## Scope and architectural complexity beyond this chapter

The GenAI application types described in this chapter represent **baseline** and commonly deployed architectural patterns. In practice, real-world GenAI systems are often more complex, specialized, and layered, even within a single category such as agentic AI.

Examples of architectures **intentionally out of scope** for this chapter include:

- **Multi-agent systems**, where multiple LLM-based agents collaborate, delegate tasks, negotiate outcomes, or supervise one another
- **Hierarchical agent architectures**, involving planners, executors, critics, and memory managers
- **Cross-model orchestration**, where different models with distinct trust levels share context and decisions
- **Domain-specific agent frameworks**, tightly coupled to business workflows, data pipelines, or operational tooling

These architectures introduce additional coordination layers, emergent behaviors, and amplified blast radius, but they still build upon the same foundational elements discussed earlier: prompts, context assembly, data influence, tools, memory, and feedback.

## Security principles still apply

Regardless of whether AI capabilities are:

- Embedded into an existing application, or
- Used to build an AI-first system around LLMs

the security principles derived from AI characteristics remain the baseline:

- Language and data act as **control inputs**
- **Influence paths** matter more than execution paths
- **Trust boundaries** move inside the application
- Behavior can change **without code changes**
- **Human oversight** remains a critical control

More complex architectures do not invalidate these principles—they **amplify the consequences** of ignoring them.

## Further reading and exploration

For readers interested in more advanced GenAI architectures, the following resources provide deeper exploration:

- **Multi-agent systems (LLMs):** [AutoGen — Microsoft Research](https://github.com/microsoft/autogen) (multi-agent conversation patterns)
- **Microsoft Azure — agentic AI design patterns:** [AI agent orchestration patterns](https://learn.microsoft.com/azure/architecture/ai-ml/guide/ai-agent-design-patterns) (Azure Architecture Center)
- **Anthropic — tool use and agents:** [Anthropic research](https://www.anthropic.com/research)
- **OpenAI — function calling and tools:** [Function calling](https://platform.openai.com/docs/guides/function-calling) (OpenAI API docs)
- **NIST — architecture-agnostic risk framing:** [AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) (AI RMF)
