# Project Steering: PipelineGPT

## Context
This is a hackathon project for HackUSU 2026's "Data App Factory" track, sponsored by Koch Industries, Databricks, and AWS. We have a 19-hour build window (6 PM Friday → 1 PM Saturday). The team has 3 members.

## Tech Stack
- Framework: Next.js 14 (App Router, TypeScript)
- Styling: Tailwind CSS (dark theme, bg-slate-950)
- AI: OpenAI GPT-5.1 with function calling
- Pipeline visualization: React Flow
- Code display: Monaco Editor
- Deployment: Vercel

## Coding Standards
- Use TypeScript strict mode for all files
- All types are defined in `src/types/index.ts` — import from there, never duplicate
- Use PySpark DataFrame API conventions in all generated code (never RDD)
- All generated Databricks code must start with `# Databricks notebook source`
- Use Tailwind utility classes only — no custom CSS unless absolutely necessary
- Dark theme throughout: bg-slate-950 base, bg-slate-900 cards, bg-slate-800 inputs
- Component files use PascalCase, utility files use kebab-case
- API routes in `src/app/api/[route-name]/route.ts` format

## Architecture Rules
- All state management via React useState in page.tsx — no external state libraries
- No database — all data is in-memory (React state)
- No real authentication — roles (admin/analyst) are a UI toggle
- No real AWS/Databricks API calls — deployment is simulated but looks authentic
- Governance checks are deterministic (rule-based, no AI call) — must return in <100ms
- OpenAI API key stored in `.env.local` only

## AI Integration Pattern
- Stage 1 (Intent Parsing): GPT-5.1 + function calling with forced tool_choice
- Stage 2 (Code Generation): GPT-5.1 standard completion, temperature 0.2
- Stage 3 (Validation): GPT-5.1 + function calling with forced tool_choice
- Stage 4 (Governance): Deterministic rule engine, no AI

## Databricks/AWS Conventions
- Unity Catalog: three-level namespace (catalog.schema.table)
- Delta Lake: preferred format for all persistent storage
- S3 paths: s3:// format, IAM roles for auth (never hardcode credentials)
- Notebook format: `# Databricks notebook source` first line, `display()` for output
- Use dbutils references, DBFS paths for local demo files

## Key Priorities (What Judges Care About)
1. Governance baked in — PII detection, access control, audit logging, approval workflows
2. Factory model — reusable templates + governance guardrails
3. Conversational AI — real back-and-forth chat, NOT a static form
4. Deep Databricks/AWS integration — terminology, branding, authentic workflows
5. Demo mode — one-click showcase of all features

## Testing Approach
- `npm run build` must succeed with zero errors
- Demo button must trigger full end-to-end flow
- All 6 templates must produce valid pipelines
- Test both Analyst and Admin roles for governance differences

## Commit Convention
- Commit after each major phase completion
- Use descriptive commit messages: "feat: add [description]"
- Judges check commit history — show incremental progress
