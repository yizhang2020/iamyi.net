---
title: "Study note — Prompt engineering (PE4LLM)"
date: 2026-05-02
keywords:
  - prompt engineering
  - LLM
  - study notes
  - context engineering
description: Personal notes from Prompt Engineering for LLMs—what PE is, layers of sophistication, and why LLMs complete text rather than reason like humans.
---

# Study note — Prompt engineering

## Preface

**Prompt engineering** feels more important every month: as **LLMs** get stronger, the bottleneck shifts to how well we *ask* them for work—clear goals, enough context, and guardrails so we gain productivity without baking in **hallucinations** or **insecure coding** patterns.

So I’ve been reading systematically again—not to chase hype, but to tighten how I **harness** these models in real tools and reviews. This page is my combined note from a few books and articles; the spine of it is one title I keep returning to (see below).

## What I’m reading

**[*Prompt Engineering for LLMs: The Art and Science of Building Large Language Model–Based Applications*](https://www.oreilly.com/library/view/prompt-engineering-for/9781098156145/)** — John Berryman and Albert Ziegler, O’Reilly, **November 2024** (often abbreviated **PE4LLM**).  
If you have O’Reilly access, the same title is on [O’Reilly Learning](https://learning.oreilly.com/library/view/prompt-engineering-for/9781098156145/).


I treat it as a practical bridge between “prompt tricks” and **how to design prompts inside applications** (state, tools, and safety).


## Study notes

### Before prompts: how an LLM “works” in one sentence

I start here because it sets expectations. **From PE4LLM:** at their core, LLMs are built to do one thing—**complete text**. The **prompt** is the input document (or block of text) we hand the model; **prompt engineering**, in its simplest form, is **crafting that prompt** so the **completion** contains what we need to solve the problem in front of us.

That framing matters: I’m not “having a conversation” with a person; I’m steering a **completion engine** whose next token is statistically likely, not “true.”

### What is prompt engineering (PE)?

I use **PE** to mean: **intentional design of prompts (and often the surrounding system)** so outputs are **useful, controllable, and safe**—not just “a nicer sentence.”

### Layers of sophistication (how I picture it)

**Layer 1 — Basic:** ask the model to do something **directly** in one shot.

**Layer 2 — More sophisticated:** **modify** and **augment** the user’s input before it hits the model, keep things **stateful** (carry context across turns), and let the stack **reach out**—e.g. tools and APIs so the app can read real data or act on the world, not only echo training patterns.

**Layer 3 — Agency:** give the application enough **agency** to decide *how* to pursue broad goals the user sets—still bounded by policy, tools, and review, but no longer “one static prompt per click.”

That ladder helps me decide where a project actually sits—and what failure modes (drift, tool abuse, silent wrong answers) I need to design for.

### Human thought vs. LLM completion (and hallucination)

Here’s the tension I keep re-learning: the model **picks plausible continuations**. Humans often assume text implies **intent, fact-checking, and accountability** behind it. LLMs were trained to **mimic patterns** in data—so a fake Social Security number looks like digits; a fake podcast URL looks like a URL.

That’s why **hallucinations** show up: **confident, plausible, and wrong**. It’s not a rare edge case—it’s structural if we treat the model like a trusted author instead of a **pattern engine** we verify.


## External resources (prompt & context engineering)

These are bookmarks I return to; the field moves fast, but the *ideas* stay useful:

- **[Prompt Engineering Guide](https://www.promptingguide.ai/)** — broad survey of techniques (few-shot, CoT, etc.) with a learning path.
- **[OpenAI — Prompt engineering](https://platform.openai.com/docs/guides/prompt-engineering)** — vendor docs tied to API behavior and constraints.
- **[Anthropic — Prompt engineering overview](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/overview)** — how Claude is steered; good on structure and clarity.
- **[Google AI — Gemini prompt design](https://ai.google.dev/gemini-api/docs/prompting-strategies)** — strategies and patterns for Gemini-style systems.
- **[LangChain — Prompt templates & related concepts](https://python.langchain.com/docs/concepts/prompt_templates/)** — when prompts live in *code* and pipelines, not only in a chat box.


## Revisit After a Year

AI is evolving faster than we often realize, and terms like *prompt engineering* are no longer the headline they were a year ago. Still, if we’re serious about harnessing AI effectively—whether through prompt engineering, context engineering, agentic systems, or beyond—the core discipline remains the same: **crafting the right inputs and assembling the right context**.

Learning these fundamentals doesn’t slow you down—it **strengthens your foundation** and enables you to move faster with confidence.

