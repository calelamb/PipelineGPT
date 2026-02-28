# Design: PipelineGPT — Technical Architecture

## Overview

PipelineGPT is a four-stage AI compiler that converts natural language into executable Databricks pipelines. The architecture consists of a Next.js 14 App Router frontend with server-side API routes that orchestrate calls to OpenAI GPT-5.1 and run deterministic governance checks.

---

## System Architecture

```
USER INPUT (Chat)
       │
       ▼
┌──────────────────┐     ┌──────────────────────────┐
│  ChatInterface   │────▶│  POST /api/parse-intent   │──▶ OpenAI GPT-5.1 (function calling)
│  (conversational)│     │  OR /api/refine-pipeline   │    → parsePipelineFunction schema
└──────────────────┘     └────────────┬───────────────┘
                                      │ PipelineDefinition JSON
                         ┌────────────┼────────────────────┐
                         ▼            ▼                    ▼
              ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
              │ React Flow   │  │ POST /api/   │  │ POST /api/       │
              │ Diagram      │  │ generate-code│  │ governance-check │
              │ (client)     │  │ → GPT-5.1     │  │ (deterministic)  │
              └──────────────┘  └──────┬───────┘  └────────┬─────────┘
                                       │ PySpark code       │ GovernanceCheck[]
                              ┌────────┼────────┐           │
                              ▼        ▼        ▼           ▼
                     ┌────────────┐ ┌────────┐ ┌──────────────────┐
                     │ Monaco     │ │ POST   │ │ GovernancePanel  │
                     │ Editor     │ │ /api/  │ │ (PII, access,    │
                     │ (code)     │ │validate│ │  quality, audit)  │
                     └────────────┘ │→GPT-5.1 │ └──────────────────┘
                                    └───┬────┘
                                        ▼
                                ┌────────────────┐
                                │ ExplanationPanel│
                                │ (plain English) │
                                └────────────────┘
```

---

## Data Flow

### Stage 1: Intent Parsing
- **Input:** User's natural language string
- **API:** `POST /api/parse-intent` (new pipeline) or `POST /api/refine-pipeline` (refinement)
- **AI Call:** OpenAI GPT-5.1 with `tools: [parsePipelineFunction]` and `tool_choice: forced`
- **Output:** `PipelineDefinition` JSON

### Stage 2: Code Generation
- **Input:** `PipelineDefinition` JSON
- **API:** `POST /api/generate-code`
- **AI Call:** OpenAI GPT-5.1 standard completion (temperature: 0.2) with `CODE_GENERATION_PROMPT`
- **Output:** Raw PySpark code string (Databricks notebook format)

### Stage 3: Validation & Explanation
- **Input:** `PipelineDefinition` + generated code
- **API:** `POST /api/validate`
- **AI Call:** OpenAI GPT-5.1 with `tools: [validatePipelineFunction]` and `tool_choice: forced`
- **Output:** `ValidationResult` (explanations + warnings)

### Stage 4: Governance (No AI)
- **Input:** `PipelineDefinition` + `UserRole`
- **API:** `POST /api/governance-check`
- **Logic:** Deterministic rule-based checks (PII regex, role policy lookups, step counting)
- **Output:** `GovernanceCheck[]` + `requiresApproval: boolean`

**Note:** Stages 3 and 4 run IN PARALLEL after Stage 2 completes.

---

## TypeScript Interfaces

```typescript
// ── Pipeline Definition Types ──────────────────────────

export type StepType = "source" | "transform" | "destination";

export type SourceOperation =
  | "read_csv" | "read_json" | "read_parquet" | "read_delta"
  | "read_database_table" | "read_unity_catalog" | "read_redshift" | "read_glue_catalog";

export type TransformOperation =
  | "filter" | "join" | "aggregate" | "sort" | "rename_columns" | "cast_types"
  | "clean_dates" | "deduplicate" | "fill_nulls" | "add_column" | "pivot"
  | "window_function" | "categorize";

export type DestinationOperation =
  | "write_csv" | "write_parquet" | "write_delta" | "write_database_table"
  | "write_unity_catalog" | "write_redshift" | "write_s3"
  | "email_report" | "display_output";

export type PipelineOperation = SourceOperation | TransformOperation | DestinationOperation;

export interface PipelineStepConfig {
  // Source configs
  bucket?: string;
  path?: string;
  format?: string;
  tableName?: string;
  hasHeader?: boolean;
  inferSchema?: boolean;
  // Transform configs
  column?: string;
  columns?: string[];
  condition?: string;
  joinKey?: string;
  joinType?: "inner" | "left" | "right" | "outer";
  rightSource?: string;
  rightSourceStepId?: string;
  groupBy?: string[];
  aggregations?: { column: string; function: string; alias: string }[];
  sortBy?: string[];
  sortOrder?: "asc" | "desc";
  newColumnName?: string;
  newColumnExpression?: string;
  dateColumn?: string;
  inputFormat?: string;
  outputFormat?: string;
  categories?: { name: string; condition: string }[];
  // Databricks / AWS configs
  catalog?: string;
  schema?: string;
  deltaPath?: string;
  s3Bucket?: string;
  s3Prefix?: string;
  redshiftTable?: string;
  redshiftSchema?: string;
  glueDatabase?: string;
  glueTable?: string;
  partitionBy?: string[];
  mergeCondition?: string;
  zOrderBy?: string[];
  // Destination configs
  outputPath?: string;
  outputTable?: string;
  recipient?: string;
  mode?: "overwrite" | "append" | "merge";
}

export interface PipelineStep {
  id: string;
  type: StepType;
  operation: PipelineOperation;
  label: string;
  config: PipelineStepConfig;
  dependsOn: string[];
}

export interface PipelineSchedule {
  frequency: "once" | "hourly" | "daily" | "weekly" | "monthly";
  dayOfWeek?: string;
  time?: string;
  cronExpression?: string;
}

export interface PipelineDefinition {
  pipelineName: string;
  description: string;
  schedule: PipelineSchedule | null;
  steps: PipelineStep[];
}

// ── Validation Types ─────────────────────────────────

export interface StepExplanation {
  stepId: string;
  plainEnglish: string;
}

export interface StepWarning {
  stepId: string;
  message: string;
  severity: "low" | "medium" | "high";
}

export interface ValidationResult {
  status: "pass" | "warning" | "error";
  explanations: StepExplanation[];
  warnings: StepWarning[];
}

// ── Governance Types ─────────────────────────────────

export type UserRole = "admin" | "analyst" | "viewer";

export interface GovernancePolicy {
  allowedSources: string[];
  blockedSources: string[];
  allowedDestinations: string[];
  maxSteps: number;
  requireApproval: boolean;
  piiColumns: string[];
  dataMaskingEnabled: boolean;
  allowedCatalogs: string[];
  allowedSchemas: string[];
}

export interface GovernanceCheck {
  rule: string;
  status: "pass" | "warning" | "fail";
  message: string;
  details?: string;
}

export interface AuditLogEntry {
  timestamp: string;
  user: string;
  action: string;
  pipelineName: string;
  details: string;
}

export interface PipelineTemplate {
  id: string;
  name: string;
  description: string;
  category: "etl" | "analytics" | "quality" | "reporting";
  icon: string;
  defaultPrompt: string;
  requiredSources: string[];
  governanceLevel: "low" | "medium" | "high";
  steps: number;
}

// ── Chat Types ───────────────────────────────────────

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: number;
  pipeline?: PipelineDefinition;
  isRefining?: boolean;
}

// ── UI State Types ───────────────────────────────────

export interface AppState {
  chatMessages: ChatMessage[];
  userInput: string;
  pipeline: PipelineDefinition | null;
  generatedCode: string | null;
  validation: ValidationResult | null;
  governanceChecks: GovernanceCheck[];
  isParsingIntent: boolean;
  isGeneratingCode: boolean;
  isValidating: boolean;
  isCheckingGovernance: boolean;
  error: string | null;
  selectedStepId: string | null;
  currentRole: UserRole;
  showTemplates: boolean;
  activeTemplate: PipelineTemplate | null;
}

// ── React Flow Node Types ────────────────────────────

export interface PipelineNodeData {
  label: string;
  stepType: StepType;
  operation: PipelineOperation;
  explanation?: string;
  warning?: StepWarning;
  isSelected?: boolean;
}
```

---

## API Route Definitions

### `POST /api/parse-intent`
- **Request:** `{ input: string }`
- **Response:** `PipelineDefinition`
- **Errors:** 500 `{ error: string }`

### `POST /api/generate-code`
- **Request:** `{ pipeline: PipelineDefinition }`
- **Response:** `{ code: string }`
- **Errors:** 500 `{ error: string }`

### `POST /api/validate`
- **Request:** `{ pipeline: PipelineDefinition, code: string }`
- **Response:** `ValidationResult`
- **Errors:** 500 `{ error: string }`

### `POST /api/governance-check`
- **Request:** `{ pipeline: PipelineDefinition, role: UserRole }`
- **Response:** `{ checks: GovernanceCheck[], requiresApproval: boolean }`

### `POST /api/refine-pipeline`
- **Request:** `{ existingPipeline: PipelineDefinition, refinement: string }`
- **Response:** `PipelineDefinition`
- **Errors:** 500 `{ error: string }`

---

## OpenAI Function Schemas

### parsePipelineFunction
Constrained schema for intent parsing. Forces GPT-5.1 to output a valid `PipelineDefinition` with:
- `pipelineName` (string, snake_case)
- `description` (string, one sentence)
- `schedule` (object with frequency/dayOfWeek/time/cronExpression, or null)
- `steps` (array of PipelineStep objects with id, type, operation, label, config, dependsOn)

Operations enum includes all Databricks/AWS-specific operations: `read_delta`, `read_unity_catalog`, `read_redshift`, `read_glue_catalog`, `write_delta`, `write_unity_catalog`, `write_redshift`, `write_s3`.

### validatePipelineFunction
Constrained schema for validation output:
- `explanations` (array of {stepId, plainEnglish})
- `warnings` (array of {stepId, message, severity: "low"|"medium"|"high"})

---

## Governance Rules Engine

Hardcoded in `src/lib/governance-rules.ts`:

### Role Policies
| Role | Allowed Sources | Blocked Destinations | Max Steps | Requires Approval | Data Masking | Allowed Catalogs |
|------|----------------|---------------------|-----------|-------------------|--------------|-----------------|
| Admin | All (*) | None | 50 | No | Off | All (*) |
| Analyst | CSV, Delta, Unity Catalog, Parquet, JSON, Glue | Redshift, Unity Catalog (prod) | 15 | Yes | On | main, analytics |
| Viewer | Unity Catalog, Delta | CSV, Redshift, Glue | 5 | Yes | On | main (reporting only) |

### PII Detection Patterns
Regex patterns scanned against all column names referenced in pipeline configs:
`/email/i`, `/phone/i`, `/ssn/i`, `/social.?security/i`, `/birth.?date/i`, `/dob/i`, `/salary/i`, `/address/i`, `/zip.?code/i`, `/credit.?card/i`, `/passport/i`, `/driver.?license/i`, `/first.?name/i`, `/last.?name/i`, `/full.?name/i`

---

## System Prompts

### INTENT_PARSE_PROMPT
Instructs GPT-5.1 to act as a data pipeline architect. Includes:
- Rules for identifying sources, transforms, destinations, dependencies
- Databricks/AWS context: Unity Catalog preferences, Delta Lake defaults, S3 paths, Redshift, Glue
- Available demo data sources (sample CSVs, Unity Catalog examples, S3 examples)

### CODE_GENERATION_PROMPT
Instructs GPT-5.1 to generate Databricks notebook code. Includes:
- `# Databricks notebook source` as first line
- Delta Lake read/write patterns
- Unity Catalog three-level namespace
- DeltaTable.forPath MERGE for upserts
- `display()` for output, `dbutils` references
- S3 via instance profiles, Redshift JDBC, Glue Catalog
- Z-ORDER optimization comments

### VALIDATION_PROMPT
Instructs GPT-5.1 to review pipeline and code, producing:
- Plain-English explanations (no jargon)
- Warnings with severity levels

---

## UI Layout

```
┌──────────────────────────────────────────────────────────────┐
│  Header: "PipelineGPT" + tagline    [👤 Analyst | 🔧 Admin]  │
│          "Powered by Databricks + AWS"      [📋 Templates]   │
├────────────────────┬─────────────────────────────────────────┤
│                    │  ┌─────────────────────────────────┐    │
│  Chat Interface    │  │  Pipeline Diagram (React Flow)  │    │
│  (35% width)       │  └─────────────────────────────────┘    │
│                    │  ┌────────────────┬────────────────┐    │
│  [user bubble]     │  │ Code Preview   │  Explanation   │    │
│  [assistant reply] │  │ (Monaco)       │  Panel         │    │
│  [user refinement] │  ├────────────────┴────────────────┤    │
│  [assistant reply] │  │ Governance & Compliance Panel   │    │
│                    │  ├─────────────────────────────────┤    │
│  ─────────────     │  │ Deploy Panel (collapsible)      │    │
│  [input bar]       │  │ (65% width)                     │    │
├────────────────────┴─────────────────────────────────────────┤
│  Footer: "Built at HackUSU 2026 • Data App Factory Track"   │
└──────────────────────────────────────────────────────────────┘
```

---

## Component Tree

```
page.tsx (main page — state management)
├── Header
│   ├── Logo + Tagline ("Powered by Databricks + AWS")
│   ├── Templates Button → TemplateLibrary (modal)
│   ├── RoleToggle (👤 Analyst | 🔧 Admin)
│   ├── Demo Button
│   └── Reset Button
├── Left Column (35%)
│   └── ChatInterface
│       ├── Message List (user/assistant bubbles)
│       ├── Typing Indicator
│       ├── Template Cards (when empty)
│       ├── Example Pills (when empty)
│       └── Input Bar (text + send button)
├── Right Column (65%)
│   ├── PipelineDiagram (React Flow)
│   │   └── PipelineNode (custom node component)
│   ├── Row: CodePreview (Monaco) | ExplanationPanel
│   ├── GovernancePanel
│   │   ├── Overall Status Badge
│   │   ├── Check List (PII, Access, Quality, Catalog, Complexity, Masking)
│   │   ├── Approval Flow (role-dependent)
│   │   └── Audit Log (collapsible)
│   └── DeployPanel (collapsible)
│       ├── Databricks Config (notebook path, cluster, runtime)
│       ├── AWS Config (S3, IAM, region)
│       ├── Schedule Display
│       ├── Delta Lake Output Config
│       └── Deploy Button + Progress Steps
└── Footer

TemplateLibrary (modal overlay)
├── Category Tabs (All, ETL, Analytics, Quality, Reporting)
└── Template Cards Grid (2 columns)
    └── Card: icon, name, description, governance badge, step count, "Use Template →"
```

---

## File Structure

```
src/
├── app/
│   ├── page.tsx                     # Main page — two-column layout with chat + results
│   ├── layout.tsx                   # Root layout (dark theme, meta tags)
│   ├── globals.css                  # Tailwind imports + custom styles
│   └── api/
│       ├── parse-intent/route.ts    # Stage 1: NL → pipeline JSON
│       ├── generate-code/route.ts   # Stage 2: pipeline JSON → PySpark
│       ├── validate/route.ts        # Stage 3: code → explanations + warnings
│       ├── governance-check/route.ts# Stage 4: governance & compliance checks
│       └── refine-pipeline/route.ts # Conversational refinement
├── components/
│   ├── PipelineNode.tsx             # Custom React Flow node
│   ├── PipelineDiagram.tsx          # React Flow pipeline visualization
│   ├── ChatInterface.tsx            # Conversational chat interface
│   ├── CodePreview.tsx              # Monaco Editor code display
│   ├── ExplanationPanel.tsx         # Plain-English explanations + warnings
│   ├── GovernancePanel.tsx          # Governance checks, PII, access, audit log
│   ├── DeployPanel.tsx              # Simulated Databricks/AWS deployment
│   ├── TemplateLibrary.tsx          # Pipeline template selector (modal)
│   ├── RoleToggle.tsx               # Admin/Analyst view switcher
│   └── LoadingSkeleton.tsx          # Reusable loading skeletons
├── lib/
│   ├── openai.ts                    # OpenAI client initialization
│   ├── prompts.ts                   # All system prompts (intent, codegen, validation)
│   ├── functions.ts                 # OpenAI function calling schemas
│   ├── governance-rules.ts          # Hardcoded governance policies & PII detection
│   └── pipeline-to-nodes.ts        # Pipeline JSON → React Flow nodes/edges
├── types/
│   └── index.ts                     # All TypeScript type definitions
└── data/
    ├── templates.ts                 # 6 pre-built pipeline templates
    ├── sample-sales.csv             # Demo dataset
    ├── sample-customers.csv         # Demo dataset
    ├── sample-employees.csv         # Demo dataset
    └── pipeline-examples.json       # Example prompts for the chat
```

---

## Design Decisions

1. **Function calling over raw completion for Stages 1 & 3:** Constrains the model to output valid JSON matching our schema — no hallucinated formats.
2. **Deterministic governance (no AI):** Fast (<100ms), predictable, auditable. Judges can see governance isn't a black box.
3. **Two-column layout (ChatGPT + artifacts style):** Familiar pattern for AI-assisted tools. Chat maintains conversational context on the left; results appear on the right.
4. **In-memory state only:** React useState — no database. 19-hour hackathon constraint.
5. **Simulated deployment:** Looks authentic with real Databricks/AWS terminology (Job IDs, IAM ARNs, S3 paths, cluster types) but doesn't make real API calls.
6. **Dark theme:** Premium feel (Linear/Vercel aesthetic) — makes pipeline diagrams and code pop visually.

---

## Design Palette

- Background: `bg-slate-950`
- Surface/cards: `bg-slate-900 border border-slate-800`
- Input fields: `bg-slate-800 border-slate-700 text-white`
- Primary accent: `indigo-500` / `indigo-600`
- Source nodes: `bg-blue-500/10 border-blue-500 text-blue-400`
- Transform nodes: `bg-amber-500/10 border-amber-500 text-amber-400`
- Destination nodes: `bg-green-500/10 border-green-500 text-green-400`
- Warning badges: yellow (low), orange (medium), red (high)
- Text: `text-white` headings, `text-slate-400` secondary
