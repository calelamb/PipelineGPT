# StackForge — AI Data App Factory

> **HackUSU 2026** · Data App Factory Track · February 27–28, 2026

---

## The Problem

Business teams need data visibility — supplier performance dashboards, cost breakdowns, quality monitors — but building them requires SQL, Python, and weeks of engineering time. The gap between "I need to see this data" and "here's an interactive dashboard" is massive.

## Our Solution

StackForge is an AI-powered platform where business users describe what they want to see in plain English and get back a live, interactive data application — charts, filters, KPIs, and tables — with enterprise governance baked in. Then they iterate on it conversationally, just like talking to an analyst.

Type this:

> "Show me supplier defect rates by region, highlight anyone above 5%, and let me filter by product category."

Get this:

1. **Interactive Plotly charts** — bar, line, pie, scatter, area with hover, zoom, and drill-down
2. **KPI cards** — key metrics at a glance with intelligent formatting (currency, percentage, number)
3. **Filterable data tables** — sortable, searchable, exportable
4. **AI narration** — plain-English explanations of what every chart and metric means
5. **Governance compliance** — PII detection, role-based access, persistent audit logging

Then refine iteratively: "Break that down by quarter" → Dashboard updates. "Add a cost impact column" → Table evolves. "Now compare that against last quarter" → New components layer in.

---

## How It Works — Five-Stage AI Engine

```
┌──────────────┐    ┌────────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  1. INTENT   │───▶│ 2. PRE-EXEC    │───▶│ 3. EXECUTE   │───▶│ 4. VALIDATE  │───▶│ 5. NARRATE   │
│   PARSING    │    │  GOVERNANCE    │    │   QUERIES    │    │  & EXPLAIN   │    │  & DELIVER   │
└──────────────┘    └────────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
  GPT-5.1 func.      SQL sanitize,         DuckDB in-mem       Data quality,       AI-generated
  calling → JSON      RBAC, column          execution →         row/column          plain-English
  app definition      access gates          DataFrames          validation          summaries
```

### Stage 1: Intent Parsing
GPT-5.1 function calling converts natural language into a structured app definition — components, SQL queries, layout, and filters. The model is constrained to output valid JSON matching a strict schema with 8 component types.

### Stage 2: Pre-Execution Governance
Before any SQL runs, deterministic checks enforce safety: SQL sanitization (blocks DROP, DELETE, UNION injection, etc.), column-level access control, component type permissions, and role capability verification. If any check fails, the pipeline halts immediately without executing queries.

### Stage 3: Execution
DuckDB executes all queries in milliseconds against the loaded dataset, producing Pandas DataFrames ready for visualization. Filter parameters are injected dynamically as subquery wrappers.

### Stage 4: Validation
Results are checked against component-specific rules — KPIs must return exactly 1 row, bar charts need 2–50 categories, pie charts need 2–12 slices, tables cap at 1,000 rows. Empty data is detected and surfaced with intelligent messages rather than blank charts.

### Stage 5: Narration
A second AI pass generates plain-English summaries — an overall dashboard narrative plus per-component explanations that describe what the data actually shows, using real numbers from the results.

---

## Key Features

### Conversational Dashboard Building
Chat-based interface where each prompt builds on the last. Start broad ("executive summary of supplier performance"), then drill down ("which suppliers have the worst quality scores?"), then pivot ("show me the cost impact of those quality issues"). The AI maintains context across the conversation.

### Custom Data Upload (Drag & Drop CSV)
Upload your own CSV files directly in the sidebar. Each file is automatically registered as a queryable DuckDB table — the AI reads its schema and generates queries against your data. Upload multiple files to join across datasets. Built-in metadata tracking shows row counts, column counts, and file names for every loaded table.

### Smart Date Range Awareness
The AI automatically discovers the actual date ranges present in your data and adjusts queries accordingly. When you say "show me trends over the last year," it uses the real dates in your dataset rather than assuming today's calendar date — no more empty charts from out-of-range filters.

### Intelligent Empty Data Handling
Three-layer defense against blank dashboards: the AI prompt is seeded with actual date ranges, the pipeline detects when all or some components return empty results and surfaces helpful messages ("the filters don't match the available data"), and each chart renderer shows a styled empty state instead of a blank white box.

### The "Show Engine" Toggle
Our technical differentiator. A single toggle reveals a 4-tab inspector panel alongside the dashboard:

| Tab | Shows |
|---|---|
| Generated SQL | Every query the AI wrote, per component, with result previews |
| Data Flow | DAG visualization of table → query → component pipeline |
| Governance | Pass/block status, PII detections, column access details |
| Audit Trail | Persistent JSONL log of every governance check with timestamps |

Business users see the dashboard. Technical reviewers see the engine. Judges see both.

### Enterprise Governance
Role-based access control with three tiers, PII detection and redaction, SQL injection prevention, column-level sensitivity labels, component count limits, export controls, and a persistent audit trail. Every governance decision is logged and auditable.

| | Admin | Analyst | Viewer |
|---|---|---|---|
| Max components | 15 | 6 | 4 |
| Column access | All (including restricted) | Public + Internal | Public only |
| PII visibility | Raw data | Redacted | Redacted |
| Export | CSV, JSON, PDF | CSV, JSON | None |
| Component types | All 8 | All 8 | No tables, no scatter |
| Session timeout | 8 hours | 4 hours | 1 hour |

### 8 Component Types
KPI cards, metric highlights, bar charts, line charts, pie charts, scatter plots, area charts, and data tables — all rendered with Plotly and a cohesive DM Sans light theme.

### 6 Quick-Start Templates
Pre-built supply chain analytics dashboards: Supplier Performance, Cost Analysis, Quality Control, Logistics Overview, Regional Analysis, and Executive Summary. One click to generate a full dashboard, then iterate from there.

### Graph History & Audit History
Every generated dashboard is saved with a timestamp, title, component count, and governance status. Admins get a full audit history page with filtering by action, status (passed/blocked), and role.

---

## Architecture

```
StackForge/
├── app.py                    # Main Streamlit app (chat, rendering, sidebar)
├── config.py                 # Roles, PII patterns, templates, validation rules
├── requirements.txt
│
├── engine/                   # Five-stage AI pipeline
│   ├── pipeline.py           # Orchestration with governance gates
│   ├── intent_parser.py      # GPT-5.1 function calling → app definition
│   ├── executor.py           # DuckDB SQL execution with filter injection
│   ├── governance.py         # PII detection, RBAC, SQL sanitization, audit
│   ├── validator.py          # Result validation per component type
│   └── overview.py           # AI-generated plain-English narration
│
├── ui/                       # Frontend
│   ├── styles.py             # Full CSS theme (DM Sans, light mode)
│   ├── dashboard.py          # Dashboard renderer, Plotly charts
│   ├── engine_view.py        # 4-tab engine inspector
│   └── chat.py               # Chat interface, templates
│
├── data/
│   └── sample_data_loader.py # DuckDB connection, CSV loading, date discovery
│
└── tests/                    # 299+ tests across 13 modules
    ├── test_edge_cases.py    # 77 edge case tests
    ├── test_multi_request.py # 89 multi-request tests
    ├── test_governance.py    # PII, RBAC, SQL sanitization
    ├── test_executor.py      # Query execution
    ├── test_validator.py     # Result validation
    ├── test_csv_upload.py    # CSV upload flow
    └── ...
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Streamlit (Python) |
| AI | OpenAI GPT-5.1 — function calling for constrained app generation |
| Database | DuckDB (embedded analytical SQL engine) |
| Visualization | Plotly (interactive charts, DM Sans light theme) |
| Data | Koch Supply Chain dataset (500 rows) + custom CSV upload |
| Testing | Pytest (299+ tests, 13 modules) |

---

## Getting Started

### Prerequisites
- Python 3.10+
- OpenAI API key (GPT-5.1 access)

### Setup
```bash
git clone https://github.com/[YOUR-TEAM]/stackforge.git
cd stackforge
pip install -r requirements.txt
cp .env.example .env
# Add your OpenAI API key to .env
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501). Log in with `admin` / `admin123`.

### Running Tests
```bash
python -m pytest tests/ -q
```

---

## Demo Script

**Prompt 1 — Broad overview:**
> "Give me an executive summary of supplier performance with KPIs and charts"

**Prompt 2 — Drill down:**
> "Break this down by product category and show me which suppliers have the worst defect rates"

**Prompt 3 — Layer new analysis:**
> "Add a cost breakdown by region and compare shipping costs across suppliers"

Toggle **"Show Engine"** at any point to reveal the SQL, data flow, governance checks, and audit trail.

**Custom data demo:** Upload a CSV in the sidebar → ask a question about it → watch the AI generate queries against your data.

---

## Production Vision: Wiring Your Own Data

In the hackathon demo, StackForge runs against a Supply Chain CSV loaded into DuckDB in-memory — fully self-contained, no external connections needed.

In production, a company swaps one file (`data/sample_data_loader.py`) to point at their real data warehouse — Databricks SQL, Snowflake, Postgres, or any SQL-compatible source. The AI reads the actual table schema at runtime and generates queries against whatever data source is connected. The governance layer enforces the company's access policies. The architecture is intentionally decoupled: **data source → AI query generation → execution → visualization**. Changing the data source requires zero changes to the AI engine, dashboard renderer, or governance layer.

**Production deployment checklist:**
- Connect to Databricks SQL warehouse (swap DuckDB connection for databricks-sql-connector)
- Point at real Unity Catalog tables
- Configure role-based access policies per company org chart
- Deploy on Streamlit Community Cloud or as a Databricks App
- Add SSO/authentication layer

---

## Team

| Name | Role |
|---|---|
| Cale Lamb | UI / Frontend Lead |
| Clayton | Backend / Engine Lead |
| [Member 3] | Demo / Presentation |

## Disclosures

- AI coding assistants were used during development
- All application code was written during the hackathon (Feb 27–28, 2026)
- Third-party APIs: OpenAI
- Dataset: Supply Chain data provided by Koch Industries / generated for demo

## License

MIT
