# Requirements: PipelineGPT — Data App Factory

## Introduction

PipelineGPT is a governed, AI-powered platform for the HackUSU 2026 "Data App Factory" track (sponsored by Koch Industries, Databricks, and AWS). It empowers non-technical business users (citizen developers) to create data pipelines through a conversational chat interface, while IT admins maintain governance guardrails. The system generates visual pipeline diagrams, production-ready PySpark code for Databricks notebooks, plain-English explanations, and governance compliance checks.

**Core loop:** Conversational chat → Structured pipeline JSON → Visual DAG diagram + Generated PySpark/Databricks code + Explanations + Governance checks → Simulated Deploy to Databricks

**Tech stack:** Next.js 14 (App Router, TypeScript), Tailwind CSS, OpenAI GPT-5.1 (function calling), React Flow, Monaco Editor, Vercel AI SDK

---

## Requirements

### Requirement 1: Conversational Chat Interface
**User Story:** As a business user, I want to describe my data workflow in plain English through a conversational chat interface, so that I can build data pipelines without writing code.

**Acceptance Criteria:**
- WHEN a user types a natural language description of a data workflow and presses Enter THE SYSTEM SHALL parse the intent and generate a structured pipeline definition
- WHEN the system generates a pipeline THE SYSTEM SHALL display an assistant message in the chat summarizing the pipeline (name, step count, step list)
- WHEN a user sends a follow-up message after a pipeline is already generated THE SYSTEM SHALL treat it as a refinement request, modifying the existing pipeline while preserving unchanged steps
- WHEN a pipeline is being processed THE SYSTEM SHALL display an animated typing indicator in the chat area
- WHEN an error occurs during any processing stage THE SYSTEM SHALL display the error as a red-styled assistant message in the chat with a "Try Again" suggestion
- WHEN the chat is empty THE SYSTEM SHALL display template cards and example pills above the input bar
- WHEN the user clicks a template card THE SYSTEM SHALL auto-populate the input with the template's default prompt AND auto-send it immediately
- WHEN the user presses Enter THE SYSTEM SHALL send the message; WHEN the user presses Shift+Enter THE SYSTEM SHALL insert a newline

### Requirement 2: Intent Parsing (Stage 1 — AI Compiler)
**User Story:** As a business user, I want my plain English descriptions to be accurately converted into structured pipeline definitions, so that the system correctly understands what I need.

**Acceptance Criteria:**
- WHEN the system receives a natural language input THE SYSTEM SHALL call OpenAI GPT-5.1 with function calling using a `parsePipelineFunction` schema to produce a constrained JSON pipeline definition
- WHEN the pipeline is parsed THE SYSTEM SHALL produce a valid DAG with at least one source step and at least one destination step
- WHEN the user mentions "table" or "catalog" THE SYSTEM SHALL prefer Unity Catalog sources (`read_unity_catalog`) with `catalog.schema.table` format
- WHEN the user mentions S3 THE SYSTEM SHALL use appropriate readers with `s3://` paths
- WHEN the user mentions "data lake" or "lakehouse" THE SYSTEM SHALL default to Delta format
- WHEN the user mentions scheduling (e.g., "every Monday") THE SYSTEM SHALL include a schedule object with frequency, day, time, and cron expression
- WHEN the user mentions two data sources that need combining THE SYSTEM SHALL create separate source steps and a join step with correct `dependsOn` references
- WHEN the user mentions "Redshift" or "data warehouse" THE SYSTEM SHALL use `read_redshift`/`write_redshift` operations
- WHEN the user mentions "Glue" or "data catalog" THE SYSTEM SHALL use `read_glue_catalog`

### Requirement 3: Code Generation (Stage 2 — PySpark)
**User Story:** As a business user, I want to see real, executable PySpark code generated from my pipeline, so that I can deploy it to Databricks.

**Acceptance Criteria:**
- WHEN the system has a valid pipeline definition THE SYSTEM SHALL call OpenAI GPT-5.1 (temperature 0.2) to generate PySpark code
- WHEN code is generated THE SYSTEM SHALL start it with `# Databricks notebook source` as the first line
- WHEN code is generated THE SYSTEM SHALL use Delta Lake read/write patterns, Unity Catalog three-level namespace, `display()` for output, and `dbutils` references
- WHEN the model includes markdown code fences THE SYSTEM SHALL strip them before displaying
- WHEN code is generated THE SYSTEM SHALL display it in a Monaco Editor (read-only, vs-dark theme, Python language)
- WHEN the user clicks "Copy Code" THE SYSTEM SHALL copy to clipboard and show "Copied!" feedback
- WHEN the user clicks "Download as .py" THE SYSTEM SHALL download the code as a Python file
- WHEN code is loading THE SYSTEM SHALL show a pulsing skeleton placeholder

### Requirement 4: Validation & Explanation (Stage 3)
**User Story:** As a business user, I want plain-English explanations of what each pipeline step does and warnings about potential issues, so that I can understand and trust the generated pipeline.

**Acceptance Criteria:**
- WHEN the system has generated code THE SYSTEM SHALL call OpenAI GPT-5.1 with function calling using `validatePipelineFunction` to produce explanations and warnings
- WHEN explanations are generated THE SYSTEM SHALL display each step's explanation in simple, non-technical language (no jargon like "DataFrame" or "schema inference")
- WHEN warnings are generated THE SYSTEM SHALL display them with severity styling: yellow/💡 for low, orange/⚠️ for medium, red/🚨 for high
- WHEN the user clicks a node in the pipeline diagram THE SYSTEM SHALL scroll the explanation panel to that step's explanation and highlight it
- WHEN no step is selected THE SYSTEM SHALL display all explanations in order as a scrollable list

### Requirement 5: Governance & Compliance (Stage 4)
**User Story:** As an IT admin, I want every pipeline to be checked against governance policies before deployment, so that data access, PII handling, and quality standards are enforced.

**Acceptance Criteria:**
- WHEN a pipeline is generated THE SYSTEM SHALL run deterministic governance checks (no AI call — rule-based, <100ms response time)
- WHEN governance checks run THE SYSTEM SHALL scan all column names in pipeline configs for PII patterns (email, phone, ssn, salary, address, dob, credit card, passport, driver license, name)
- WHEN PII columns are detected AND the current role has `dataMaskingEnabled` THE SYSTEM SHALL flag which columns will be auto-masked
- WHEN any pipeline step uses an operation not in the current role's `allowedSources` or `allowedDestinations` THE SYSTEM SHALL flag it as an access control failure
- WHEN the pipeline references Unity Catalog catalogs/schemas not in the role's allowed list THE SYSTEM SHALL flag a catalog access failure
- WHEN a pipeline has more steps than the role's `maxSteps` THE SYSTEM SHALL flag it as high complexity requiring admin approval
- WHEN any CSV source lacks schema inference THE SYSTEM SHALL flag a data quality warning
- WHEN all checks pass THE SYSTEM SHALL display a green "Compliant" badge; WHEN there are warnings THE SYSTEM SHALL display yellow "Review Required"; WHEN there are failures THE SYSTEM SHALL display red "Non-Compliant"
- WHEN the role requires approval THE SYSTEM SHALL show "Requires Admin Approval" banner with appropriate action button per role

### Requirement 6: Role-Based Access Control
**User Story:** As an IT admin, I want to toggle between Admin and Analyst views, so that I can demonstrate how different roles experience different governance guardrails.

**Acceptance Criteria:**
- WHEN the page loads THE SYSTEM SHALL default to the "Analyst" role
- WHEN the user clicks the role toggle THE SYSTEM SHALL switch between "👤 Analyst" and "🔧 Admin" views
- WHEN the role changes THE SYSTEM SHALL re-run governance checks with the new role's policies
- WHEN in Analyst view THE SYSTEM SHALL show governance restrictions, "Submit for Approval" deploy button, restricted template access, and masked PII columns
- WHEN in Admin view THE SYSTEM SHALL show "Full Access", "Approve Pipeline" button, "Deploy to Databricks" deploy button, all templates, and full audit log

### Requirement 7: Pipeline Template Library
**User Story:** As a business user, I want to start from pre-configured pipeline templates, so that I can quickly build common data workflows without starting from scratch.

**Acceptance Criteria:**
- WHEN the user clicks "📋 Templates" in the header THE SYSTEM SHALL open a template library modal/panel
- WHEN the template library opens THE SYSTEM SHALL display 6 Databricks/AWS templates in a grid with category tabs (All, ETL, Analytics, Quality, Reporting)
- WHEN a template card is displayed THE SYSTEM SHALL show: category icon, template name, description, governance level badge (Low/Medium/High), expected step count, and "Use Template →" button
- WHEN the user clicks "Use Template →" THE SYSTEM SHALL close the library, populate the chat with the template's default prompt, and auto-send it
- THE SYSTEM SHALL include these templates: S3 to Delta Lake ETL, Customer 360 View, Data Quality Audit, Weekly Sales Report, Incremental Data Sync, Cross-Source Join

### Requirement 8: Visual Pipeline Diagram
**User Story:** As a business user, I want to see a visual diagram of my data pipeline, so that I can understand the flow of data through each step.

**Acceptance Criteria:**
- WHEN a pipeline is generated THE SYSTEM SHALL render it as a React Flow node graph with left-to-right flow
- WHEN nodes are rendered THE SYSTEM SHALL color them by type: blue for source (📥), amber for transform (⚙️), green for destination (📤)
- WHEN a node has a warning THE SYSTEM SHALL show a colored warning dot in the top-right corner
- WHEN the user clicks a node THE SYSTEM SHALL select it (glow ring) and update the explanation panel
- WHEN no pipeline exists THE SYSTEM SHALL show an empty state: "Your pipeline will appear here"
- WHEN the pipeline definition changes (via refinement) THE SYSTEM SHALL re-render the diagram with the updated steps

### Requirement 9: Simulated Databricks Deployment
**User Story:** As a business user, I want to simulate deploying my pipeline to Databricks, so that I can see how the deployment workflow would work in production.

**Acceptance Criteria:**
- WHEN the user clicks the deploy button THE SYSTEM SHALL simulate a 5-step deployment: creating notebook (0.5s), configuring IAM (0.5s), registering job (0.5s), setting up Delta output (0.5s), scheduling (0.5s)
- WHEN deployment completes THE SYSTEM SHALL show success with: green checkmark, fake Job ID, notebook path, S3 output location, Delta table location, next scheduled run, and "Open in Databricks ↗" link
- WHEN the deploy panel is visible THE SYSTEM SHALL show configuration for: Databricks workspace (notebook path, cluster type, runtime), AWS infrastructure (S3 bucket, IAM role, region), schedule, and Delta Lake output
- WHEN no pipeline exists THE SYSTEM SHALL disable the deploy button

### Requirement 10: Demo Mode
**User Story:** As a presenter, I want a one-click demo that showcases the full PipelineGPT flow including conversational refinement and role switching, so that judges can see all features in action.

**Acceptance Criteria:**
- WHEN the user clicks the "Demo" button THE SYSTEM SHALL auto-send a pre-written pipeline request as a chat message
- WHEN the initial pipeline is built THE SYSTEM SHALL wait 2 seconds then auto-send a follow-up refinement request ("add deduplication before the join, mask customer email column")
- WHEN the refinement completes THE SYSTEM SHALL switch from Analyst to Admin view to show the approval flow and audit log
- WHEN the "Reset" button is clicked THE SYSTEM SHALL clear all state (chat, pipeline, code, governance) and return to the empty state
- WHEN Demo mode runs THE SYSTEM SHALL start in Analyst view to show governance restrictions first

---

## Non-Functional Requirements

### NFR 1: Performance
- WHEN a governance check is triggered THE SYSTEM SHALL return results in under 100ms (no AI call — deterministic rules only)
- WHEN the full pipeline flow runs THE SYSTEM SHALL complete all 4 stages (parse → code → validate → governance) in under 15 seconds total

### NFR 2: Visual Design
- THE SYSTEM SHALL use a dark theme (bg-slate-950) that feels like a premium developer tool (Linear, Vercel Dashboard aesthetic)
- THE SYSTEM SHALL use a two-column layout: chat (35% width) on the left, results (65% width) on the right
- THE SYSTEM SHALL optimize for laptop screens (1280-1440px width)

### NFR 3: Hackathon Constraints
- THE SYSTEM SHALL NOT use a database — all state in React useState (in-memory)
- THE SYSTEM SHALL NOT implement real authentication — roles are a UI toggle only
- THE SYSTEM SHALL NOT make real AWS/Databricks API calls — deployment is simulated but looks authentic
- THE SYSTEM SHALL store the OpenAI API key in `.env.local` (never hardcoded)
