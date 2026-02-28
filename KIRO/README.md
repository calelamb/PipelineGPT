# PipelineGPT — Kiro Build Guide

> **HackUSU 2026** · Data App Factory Track · February 27–28, 2026

---

## Quick Start with Kiro

This folder is optimized for building PipelineGPT using **Kiro IDE's spec-driven workflow**. All specs are pre-written and ready to go.

### Setup

1. Open this `KIRO/` folder as your project root in Kiro IDE
2. Kiro will automatically detect the specs in `.kiro/specs/pipeline-gpt/`
3. The steering file at `.kiro/steering/project.md` provides project context

### Kiro Specs Structure

```
KIRO/
├── .kiro/
│   ├── specs/
│   │   └── pipeline-gpt/
│   │       ├── requirements.md    ← User stories + EARS acceptance criteria
│   │       ├── design.md          ← Technical architecture + TypeScript interfaces
│   │       └── tasks.md           ← 32 sequenced implementation tasks
│   └── steering/
│       └── project.md             ← Project context, coding standards, priorities
└── README.md                      ← This file
```

### How to Use

1. **Reference the spec** — Type `#spec` in Kiro chat and select `pipeline-gpt` to include all spec context
2. **Follow the tasks** — Tasks are sequenced in 6 phases with dependency tracking. Work through them in order.
3. **Check off tasks** — Mark tasks complete in `tasks.md` as you go. Kiro tracks progress.
4. **Commit at milestones** — Each phase has a suggested commit message

### Build Phases

| Phase | Hours | What Gets Built |
|-------|-------|----------------|
| 1. Foundation | 0-2 | Types, OpenAI client, prompts, schemas, utilities |
| 2. API Routes | 2-5 | 5 API routes (parse, generate, validate, governance, refine) |
| 3. Core UI | 5-10 | 10 React components (chat, diagram, code, governance, etc.) |
| 4. Assembly | 10-13 | Main page with full state management and wiring |
| 5. Demo & Polish | 13-16 | Demo mode, loading states, transitions, UX polish |
| 6. Verification | 16-17 | Testing all features, build check, final commit |

### Key Files to Reference

The spec files contain everything Kiro needs:

- **requirements.md** — 10 functional requirements + 3 non-functional requirements, all in EARS notation with testable acceptance criteria
- **design.md** — Complete TypeScript interfaces, API route definitions, system architecture, component tree, file structure, OpenAI function schemas, governance rules engine spec, UI layout diagram, design palette
- **tasks.md** — 32 implementation tasks across 6 phases, each with sub-steps, requirement tracebacks, and commit points

### Steering Context

The steering file tells Kiro about:
- Tech stack and coding standards
- Architecture rules (no database, no real auth, simulated deployment)
- Databricks/AWS naming conventions
- What judges care about (governance, factory model, conversational AI, deep integration)
- Commit conventions

---

## What We're Building

PipelineGPT is a governed, AI-powered platform where business users describe data workflows through a conversational chat interface. The system generates:

1. **Visual pipeline diagrams** (React Flow DAG)
2. **Production-ready PySpark code** (Databricks notebook format)
3. **Plain-English explanations** (what each step does + warnings)
4. **Governance compliance checks** (PII detection, access control, audit logging)
5. **Simulated Databricks deployment** (authentic-looking AWS/Databricks workflow)

### Architecture: Four-Stage AI Compiler

```
Chat Input → [Stage 1: Parse Intent (GPT-5.1 function calling)]
          → [Stage 2: Generate Code (GPT-5.1 completion)]
          → [Stage 3: Validate (GPT-5.1 function calling)]  } parallel
          → [Stage 4: Governance (deterministic rules)]     }
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 14 (App Router, TypeScript) |
| Styling | Tailwind CSS (dark theme) |
| AI | OpenAI GPT-5.1 — function calling + completion |
| Pipeline Viz | React Flow |
| Code Display | Monaco Editor |
| Deploy | Vercel |

---

## Team

| Name | Role |
|------|------|
| [Member 1] | AI / Backend Lead |
| [Member 2] | Frontend / UX Lead |
| [Member 3] | Integration / DevOps + Demo |

## Disclosures

- AI coding assistants (Kiro IDE) used during development
- All application code written during the hackathon (Feb 27–28, 2026)
- Third-party APIs: OpenAI
- Static data files prepared before the event
