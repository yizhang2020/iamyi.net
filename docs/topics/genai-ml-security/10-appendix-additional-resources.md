---
title: "10. Appendix — additional resources"
keywords:
  - GenAI
  - MLSecOps
  - OWASP
  - reading list
description: >
  Curated links and references consulted while building this minibook—threat modeling, OWASP
  cheat sheets, MLSecOps, tools, and further reading.
date: 2026-05-02
---

# 10. Appendix — additional resources

While working through SANS training and organizing these notes, I **consulted and recommend** the following materials for readers who want to go deeper. (Yi, 1/5/2026)

Entries are **deduplicated**; some titles appear in both industry articles and open-source repos under slightly different names.

## Threat modeling & design

- [Deciduous](https://deciduous.app) — decision tree generator for threat modeling  
- [Streamlit](https://streamlit.io) — common framework for quick ML/security engineering dashboards and prototypes  

## OWASP cheat sheets (GenAI / ML)

- [LLM prompt injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) — OWASP Cheat Sheet Series  
- [Secure AI model ops](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html) — OWASP Cheat Sheet Series  
- [AI agent security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) — OWASP Cheat Sheet Series  

## Platforms, pipelines, and MLSecOps

- [MLflow](https://mlflow.org/) — open-source platform for agents, LLMs, and experiment tracking  
- [LLMOps tools (market guide)](https://research.aimultiple.com/llmops-tools/) — AI Multiple *(ML lifecycle tooling; pair with MLSecOps practices and your org’s controls)*  
- [Awesome MLSecOps](https://github.com/RiccardoBiosas/awesome-MLSecOps) — curated list (GitHub)  
- [SAI #21: What is continuous training (CT) in machine learning systems?](https://www.linkedin.com/pulse/sai-21-what-continuous-ct-machine-learning-systems-rajiv-sharma/) — *example industry article series; substitute your preferred vendor-neutral source if needed*  

## Model tooling, scanners, and robustness

- [Trusted-AI Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) (ART) — GitHub  
- [Netron](https://github.com/lutzroeder/netron) — model visualization  
- [ModelAudit vs ModelScan: comparing ML model security scanners](https://www.promptfoo.dev/docs/model-audit-vs-modelscan/) — Promptfoo *(if URL moves, search Promptfoo + ModelAudit + ModelScan)*  
- [4M models scanned: Protect AI + Hugging Face](https://huggingface.co/blog/protectai) — Hugging Face / Protect AI collaboration *(title paraphrased; see HF blog for current post)*  
- [Unsloth](https://github.com/unslothai/unsloth) — train and run models locally (efficient fine-tuning)  
- [ThalesGroup / secure-ml](https://github.com/ThalesGroup/secure-ml) — secure ML framework (requirements, guidelines, tools)  

## Agents, computer use, and memory

- [Security of AI agents](https://research.aimultiple.com/security-of-ai-agents/) — AI Multiple (15 threat themes, OWASP-aligned framing)  
- [Top agentic AI design patterns for architecting AI systems](https://learn.microsoft.com/azure/architecture/ai-ml/guide/ai-agent-design-patterns) — Microsoft Azure Architecture Center  
- [Agentic AI security: what it is and how to do it](https://research.aimultiple.com/agentic-ai-security/) — AI Multiple *(overview; diagrams live on their site)*  
- [Computer-using agent (OpenAI)](https://openai.com/index/computer-using-agent/) — OpenAI announcement / product page *(URL may update)*  
- [trycua / cua](https://github.com/trycua/cua) — open infrastructure for computer-use agents (sandboxes, SDKs)  
- [Memory Bank (Cline)](https://github.com/cline/memory-bank) — persistent context patterns for agentic coding assistants  

## RAG, vectors, and infrastructure

- [Powerful comparison: HNSW vs IVF indexing](https://www.pinecone.io/learn/hnsw-ivf/) — Pinecone *(introductory comparison; vendor-neutral alternatives exist)*  
- [Vector DB comparison: Pinecone vs OpenSearch](https://www.elastic.co/search-labs/blog/vector-search-opensearch-vs-pinecone) — *example comparison article; pick your preferred vendor write-up*  
- [Cross-service confused deputy prevention (Amazon OpenSearch)](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cross-service-confused-deputy-prevention.html) — AWS documentation  

## Signing, supply chain, and BOM

- [sigstore / cosign](https://github.com/sigstore/cosign) — artifact signing and verification  
- [Artifact signing and verification with Sigstore Cosign](https://blog.sigstore.dev/cosign/) — Sigstore blog *(entry point for concepts)*  
- [OWASP AIBOM Generator (Hugging Face Space)](https://huggingface.co/spaces/GenAISecurityProject/OWASP-AIBOM-Generator)  

## Evaluation, RAG tradeoffs, and training modes

- [Full fine-tuning, PEFT, prompt engineering, and RAG: which one is right for you?](https://www.philschmid.de/fine-tuning-peft-prompt-engineering-rag) — *representative explainer; many good posts exist*  
- [Large Language Model Evaluation in ’26: metrics & methods](https://research.aimultiple.com/large-language-model-evaluation/) — AI Multiple *(broad evaluation primer; “steady the course”–style framing appears in many vendor posts)*  
- [Security planning for LLM-based applications](https://learn.microsoft.com/azure/security/fundamentals/llm-security) — Microsoft *(path may change; search “LLM security planning Azure”)*  
- [The ultimate guide to LLM security: risks & practical tips](https://www.promptfoo.dev/docs/red-team/) — Promptfoo docs / red teaming *(example deep guide)*  

## Concepts & culture (not single links)

- **PAL (program-aided language models)** — start from the paper: [PAL: program-aided language models](https://arxiv.org/abs/2211.10435) (arXiv)  
- **“Ultrathink” in Claude Code** — product/workflow terminology; see current Anthropic / Claude Code documentation.  
- **ANI / AGI / ASI** — informal taxonomy of capability levels; treat as conceptual vocabulary, not a standard.  
- **Workload identity on agentic platforms** — see your platform’s IAM docs (a *Kagenti identity*–style PDF may be vendor-specific training material).  

## Cybersecurity-focused small language models

- [Are small language models the future of cybersecurity AI?](https://www.cloudnowconsulting.com/news/why-small-language-models-are-the-tailors-of-cybersecurity) — CloudNow *(example industry perspective)*  
- [Toward cybersecurity-expert small language models](https://arxiv.org/search/?query=cybersecurity+small+language+models) — search arXiv for current papers *(topic moves quickly)*  

## Semgrep, MCP, and IDE guardrails

- [Semgrep](https://semgrep.dev/) — static analysis; pairs with MCP / IDE workflows for generated code review *(see Semgrep docs for MCP server details)*  

## Jailbreaks and misuse research (examples)

- **“Do Anything Now” (DAN) / jailbreak families** — academic and industry write-ups change frequently; search for *DAN jailbreak ChatGPT* or OWASP GenAI risk entries for curated context.  
- Prefer primary sources (papers, OWASP, vendor security blogs) over orphaned `.md` filenames without a stable URL.  

*This appendix is a living list—prune duplicates, fix stale URLs, and add your own org’s internal standards where appropriate.*
