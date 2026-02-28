# StackForge — AI-Powered Data App Factory

> **HackUSU 2026** · Data App Factory Track · February 27–28, 2026

---

## The Problem

Business teams need data visibility — supplier performance dashboards, cost breakdowns, quality monitors — but building them requires SQL, Python, and weeks of engineering time. The gap between "I need to see this data" and "here's an interactive dashboard" is massive.

## Our Solution

StackForge is an AI-powered platform where business users describe what they want to see in plain English, and get back a live, interactive data application — charts, filters, KPIs, and tables — with enterprise governance baked in.

Type this:

> "Show me supplier defect rates by region, highlight anyone above 5%, and let me filter by product category."

Get this:
1. **Interactive Plotly charts** — bar, line, pie, scatter with hover, zoom, and drill-down
2. **KPI cards** — key metrics at a glance with trend indicators
3. **Filterable data tables** — sortable, searchable, exportable
4. **Governance compliance** — PII detection, role-based access, audit logging

Then refine: "Break that down by quarter" → Dashboard updates. "Add a cost impact column" → Table evolves.

## How It Works — Five-Stage AI Engine

### Stage 1: Intent Parsing
GPT-5.1 function calling converts natural language → structured app definition (components, SQL queries, layout, filters). The model is constrained to output valid JSON matching a strict schema.

### Stage 2: SQL Generation
The AI generates DuckDB SQL queries for each dashboard component — KPI aggregations, chart groupings, table selections — optimized for the Supply Chain dataset.

### Stage 3: Execution
DuckDB executes all queries in milliseconds against the Supply Chain CSV, producing Pandas DataFrames ready for visualization.

### Stage 4: Validation
Results are checked for empty data, high cardinality, failed queries. Plain-English explanations describe what each component shows.

### Stage 5: Governance
Deterministic checks: PII detection (regex), role-based access control (admin/analyst/viewer), query complexity limits, export control, and audit logging.

## The "Show Engine" Toggle

Our technical differentiator. A single toggle reveals what's happening under the hood — generated SQL queries, data transformation flow, governance audit trail, and execution details. Business users see the dashboard; technical reviewers see the engine. Judges see both.

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Streamlit (Python) |
| AI | OpenAI GPT-5.1 — function calling for constrained app generation |
| Database | DuckDB (embedded analytical SQL engine) |
| Visualization | Plotly (interactive charts with dark theme) |
| Data | Koch Supply Chain dataset (500 rows) |
| Deployment | Streamlit Community Cloud |

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

Open [http://localhost:8501](http://localhost:8501).

## Demo

Click the **"🎬 Demo"** button to see the full flow — template loads, AI parses, dashboard builds, governance checks run — all in one click.

## Templates

6 pre-built Supply Chain analytics templates:
- 📊 Supplier Performance Dashboard
- 📦 Inventory Optimization
- 💰 Supply Chain Cost Breakdown
- 🔍 Quality Control Monitor
- 🚚 Logistics & Shipping Tracker
- 📈 Executive KPI Summary

## Production Vision: Wiring Your Own Data

In the hackathon demo, StackForge runs against a single Supply Chain CSV loaded into DuckDB in-memory — fully self-contained, no external connections needed.

In production, a company swaps one file (`data/sample_data_loader.py`) to point at their real data warehouse — Databricks SQL, Snowflake, Postgres, or any SQL-compatible source. The rest of the app doesn't change.

The AI reads the actual table schema at runtime and generates queries against whatever data source is connected. The governance layer enforces the company's access policies.

The architecture is intentionally decoupled: **data source → AI query generation → execution → visualization**. Changing the data source requires zero changes to the AI engine, dashboard renderer, or governance layer.

**Production deployment checklist:**
- Connect to Databricks SQL warehouse (swap DuckDB connection for databricks-sql-connector)
- Point at real Unity Catalog tables
- Configure role-based access policies per company org chart
- Deploy on Streamlit Community Cloud or as a Databricks App
- Add SSO/authentication layer

## Team

| Name | Role |
|---|---|
| [Member 1] | AI / Backend Lead |
| [Member 2] | Frontend / UX Lead |
| [Member 3] | Integration / DevOps + Demo |

## Disclosures

- AI coding assistants were used during development
- All application code was written during the hackathon (Feb 27–28, 2026)
- Third-party APIs: OpenAI
- Dataset: Supply Chain data provided by Koch Industries / generated for demo

## Roadmap

- Databricks SQL connector (replace DuckDB with live Databricks warehouse)
- Multiple dataset support (upload your own CSV/Parquet)
- Collaborative app editing with team sharing
- App versioning and diff tracking
- Scheduled dashboard refresh via Databricks Jobs
- Export to Databricks notebook format

## License

MIT
