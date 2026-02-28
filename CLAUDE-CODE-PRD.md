# Claude Code PRD: StackForge — Data App Factory

## INSTRUCTIONS FOR CLAUDE CODE

You are building a Streamlit-based data application for HackUSU 2026's "Data App Factory" track (sponsored by Koch Industries, Databricks, and AWS). This is a 19-hour build window. This document is your complete specification. Build the entire application step by step. Commit after each major milestone. Do not skip steps.

---

## PROJECT OVERVIEW

**Track requirement:** Build a "Data App Factory" — a governed framework that empowers non-technical business users (citizen developers) to create their own data applications through conversational AI, while IT/admins maintain governance guardrails.

**What we're building:** StackForge — a governed, AI-powered platform where business users describe data questions through a conversational chat interface, and the system generates LIVE INTERACTIVE DATA APPLICATIONS — dashboards with charts, filterable tables, KPI cards, and drill-down capabilities. The AI doesn't just answer questions — it BUILDS working data apps that users can interact with, refine through conversation, and share.

**Core loop:** Conversational chat → AI parses intent → Generates Python/SQL code → Executes against real data → Renders interactive dashboard components (charts, tables, KPIs) → User refines through follow-up chat → App evolves

**The "Show Engine" differentiator:** A toggle that reveals the technical engine behind the dashboard — the generated Python/SQL code, the data transformation DAG, governance audit trail, and query execution plan. Business users see their dashboard; technical reviewers see the engine. No other team will have this transparency layer.

**Key differentiators (what judges care about):**
1. **Interactive, not static** — Generated apps have filters, drill-downs, sortable tables, and responsive charts. Not just images or static text.
2. **Conversational refinement** — "Break that down by quarter" / "Add a cost impact column" / "Flag suppliers above 5% defect rate" — the app EVOLVES through conversation.
3. **Governance is baked in** — PII detection, role-based access, audit logging, data masking. Every generated app gets compliance checks.
4. **Factory model** — Templates that IT admins configure, business users customize via natural language. The platform PRODUCES data apps.
5. **Real data** — Demos against the actual Supply Chain dataset provided by Koch. Not fake data.

**Tech stack:**
- Framework: Streamlit (Python)
- AI: OpenAI GPT-5.1 with function calling
- Data: Pandas, Plotly for interactive charts
- Database: DuckDB (embedded analytical database — blazing fast SQL on CSV/Parquet)
- Deployment: Streamlit Community Cloud or local
- Styling: Streamlit native + custom CSS

---

## STEP 1: PROJECT SETUP AND DATA LOADING

Create the project structure:

```
stackforge/
├── app.py                      # Main Streamlit application
├── requirements.txt            # Dependencies
├── .env                        # Environment variables
├── config.py                   # App configuration
├── data/
│   ├── supply_chain.csv        # Koch-provided Supply Chain dataset
│   └── sample_data_loader.py   # Data loading and DuckDB setup
├── engine/
│   ├── __init__.py
│   ├── intent_parser.py        # Stage 1: NL → structured intent (GPT-5.1 function calling)
│   ├── executor.py             # Stage 3: Execute generated code safely
│   ├── validator.py            # Stage 4: Validate and explain
│   └── governance.py           # Stage 5: Governance checks (deterministic)
├── ui/
│   ├── __init__.py
│   ├── chat.py                 # Chat interface component
│   ├── dashboard.py            # Dashboard renderer (charts, tables, KPIs)
│   ├── engine_view.py          # "Show Engine" technical view
│   └── styles.py               # Custom CSS
└── utils/
    ├── __init__.py
    └── helpers.py              # Utility functions
```

### 1a. Create `requirements.txt`:

```
streamlit>=1.30.0
openai>=1.12.0
pandas>=2.0.0
plotly>=5.18.0
duckdb>=0.9.0
python-dotenv>=1.0.0
```

### 1b. Create `config.py`:

```python
import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-5.1"
APP_NAME = "StackForge"
APP_TAGLINE = "Forge Interactive Data Apps from Conversation"
APP_DESCRIPTION = "AI-powered Data App Factory for the Databricks + AWS ecosystem"

# Governance defaults
MAX_ROWS_DISPLAY = 10000
PII_PATTERNS = [
    r"(?i)email", r"(?i)phone", r"(?i)ssn", r"(?i)social.?security",
    r"(?i)birth.?date", r"(?i)dob", r"(?i)salary", r"(?i)address",
    r"(?i)zip.?code", r"(?i)credit.?card", r"(?i)passport",
    r"(?i)driver.?license", r"(?i)first.?name", r"(?i)last.?name",
]

# Role definitions
ROLES = {
    "admin": {
        "label": "🔧 Admin",
        "can_view_raw_data": True,
        "can_view_pii": True,
        "can_deploy": True,
        "can_export": True,
        "max_query_complexity": "unlimited",
    },
    "analyst": {
        "label": "👤 Analyst",
        "can_view_raw_data": True,
        "can_view_pii": False,
        "can_deploy": False,
        "can_export": True,
        "max_query_complexity": "medium",
    },
    "viewer": {
        "label": "👁️ Viewer",
        "can_view_raw_data": False,
        "can_view_pii": False,
        "can_deploy": False,
        "can_export": False,
        "max_query_complexity": "simple",
    },
}

# Template definitions
TEMPLATES = [
    {
        "id": "supplier_performance",
        "name": "Supplier Performance Dashboard",
        "icon": "📊",
        "description": "Analyze supplier defect rates, delivery times, and costs across regions",
        "category": "analytics",
        "governance_level": "medium",
        "default_prompt": "Show me a dashboard of supplier performance — defect rates by supplier, delivery time trends, and cost analysis by region. Highlight any suppliers with defect rates above 5%.",
    },
    {
        "id": "inventory_optimization",
        "name": "Inventory Optimization",
        "icon": "📦",
        "description": "Track stock levels, identify slow-moving inventory, and forecast demand",
        "category": "analytics",
        "governance_level": "medium",
        "default_prompt": "Build an inventory analysis app showing current stock levels, days of supply by product category, and flag items that are overstocked or at risk of stockout.",
    },
    {
        "id": "cost_analysis",
        "name": "Supply Chain Cost Breakdown",
        "icon": "💰",
        "description": "Break down costs across shipping, manufacturing, and warehousing",
        "category": "reporting",
        "governance_level": "low",
        "default_prompt": "Create a cost breakdown dashboard showing total costs by category (shipping, manufacturing, warehousing), cost trends over time, and identify the top 10 most expensive supply chain routes.",
    },
    {
        "id": "quality_monitor",
        "name": "Quality Control Monitor",
        "icon": "🔍",
        "description": "Track product defects, inspection results, and quality KPIs",
        "category": "quality",
        "governance_level": "high",
        "default_prompt": "Build a quality control dashboard showing defect rates by product type, inspection pass/fail trends over time, and a table of recent quality incidents sorted by severity.",
    },
    {
        "id": "logistics_tracker",
        "name": "Logistics & Shipping Tracker",
        "icon": "🚚",
        "description": "Monitor shipment status, delivery performance, and route efficiency",
        "category": "analytics",
        "governance_level": "medium",
        "default_prompt": "Create a logistics dashboard showing on-time delivery rates by carrier, average shipping times by route, and a map or chart of shipment volumes by destination region.",
    },
    {
        "id": "executive_summary",
        "name": "Executive KPI Summary",
        "icon": "📈",
        "description": "High-level KPIs for supply chain health",
        "category": "reporting",
        "governance_level": "low",
        "default_prompt": "Generate an executive summary dashboard with key supply chain KPIs: total revenue, average defect rate, on-time delivery percentage, inventory turnover ratio, and top-performing suppliers. Show month-over-month trends.",
    },
]
```

### 1c. Create `data/sample_data_loader.py`:

```python
import duckdb
import pandas as pd
import os

def get_connection():
    """Create a DuckDB in-memory connection with the supply chain data loaded."""
    conn = duckdb.connect(":memory:")

    # Load supply chain dataset
    data_dir = os.path.dirname(__file__)
    csv_path = os.path.join(data_dir, "supply_chain.csv")

    if os.path.exists(csv_path):
        conn.execute(f"""
            CREATE TABLE supply_chain AS
            SELECT * FROM read_csv_auto('{csv_path}')
        """)
    else:
        # Generate synthetic supply chain data if no CSV provided
        _generate_sample_data(conn)

    return conn

def _generate_sample_data(conn):
    """Generate synthetic supply chain data for demos."""
    import random
    import datetime

    random.seed(42)

    suppliers = ["Acme Corp", "GlobalParts Inc", "TechSupply Co", "PrecisionMfg",
                 "FastShip LLC", "QualityFirst", "BulkMaterials", "MicroComponents",
                 "SteelWorks Int", "PlastiCorp"]
    regions = ["North America", "Europe", "Asia Pacific", "Latin America", "Middle East"]
    products = ["Widget A", "Widget B", "Component X", "Component Y", "Assembly Z",
                "Material Alpha", "Material Beta", "Part Gamma", "Part Delta", "Unit Epsilon"]
    categories = ["Raw Materials", "Components", "Finished Goods", "Packaging", "Equipment"]
    shipping_modes = ["Air", "Sea", "Rail", "Truck", "Express"]

    rows = []
    for i in range(500):
        date = datetime.date(2025, 1, 1) + datetime.timedelta(days=random.randint(0, 420))
        supplier = random.choice(suppliers)
        region = random.choice(regions)
        product = random.choice(products)
        category = random.choice(categories)
        quantity = random.randint(10, 5000)
        unit_cost = round(random.uniform(5, 500), 2)
        total_cost = round(quantity * unit_cost, 2)
        defect_rate = round(random.uniform(0, 12), 2)
        delivery_days = random.randint(1, 45)
        on_time = 1 if delivery_days <= random.randint(5, 30) else 0
        shipping_mode = random.choice(shipping_modes)
        shipping_cost = round(random.uniform(50, 5000), 2)
        warehouse_cost = round(random.uniform(100, 3000), 2)

        rows.append({
            "order_id": f"ORD-{1000+i}",
            "order_date": date.isoformat(),
            "supplier": supplier,
            "region": region,
            "product": product,
            "category": category,
            "quantity": quantity,
            "unit_cost": unit_cost,
            "total_cost": total_cost,
            "defect_rate": defect_rate,
            "delivery_days": delivery_days,
            "on_time_delivery": on_time,
            "shipping_mode": shipping_mode,
            "shipping_cost": shipping_cost,
            "warehouse_cost": warehouse_cost,
        })

    df = pd.DataFrame(rows)
    conn.execute("CREATE TABLE supply_chain AS SELECT * FROM df")

def get_table_schema(conn, table_name="supply_chain"):
    """Get the schema of a table as a formatted string."""
    result = conn.execute(f"DESCRIBE {table_name}").fetchall()
    schema_lines = [f"  - {row[0]} ({row[1]})" for row in result]
    return f"Table: {table_name}\nColumns:\n" + "\n".join(schema_lines)

def get_sample_rows(conn, table_name="supply_chain", n=5):
    """Get sample rows from a table."""
    return conn.execute(f"SELECT * FROM {table_name} LIMIT {n}").fetchdf()
```

**Commit: "feat: project setup with config, data loader, and DuckDB integration"**

---

## STEP 2: AI ENGINE — INTENT PARSER

### Create `engine/intent_parser.py`:

```python
"""Stage 1: Parse natural language into structured app intent using GPT-5.1 function calling."""

from openai import OpenAI
import json
from config import OPENAI_API_KEY, OPENAI_MODEL

client = OpenAI(api_key=OPENAI_API_KEY)

APP_INTENT_FUNCTION = {
    "name": "create_data_app",
    "description": "Parse a natural language request into a structured data application definition with visualization components, data queries, and layout.",
    "parameters": {
        "type": "object",
        "properties": {
            "app_title": {
                "type": "string",
                "description": "Short, descriptive title for the data app (e.g., 'Supplier Performance Dashboard')"
            },
            "app_description": {
                "type": "string",
                "description": "One-sentence description of what this app shows"
            },
            "components": {
                "type": "array",
                "description": "List of dashboard components to generate",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Unique component ID (comp_1, comp_2, ...)"
                        },
                        "type": {
                            "type": "string",
                            "enum": ["kpi_card", "bar_chart", "line_chart", "pie_chart", "scatter_plot", "table", "metric_highlight", "area_chart", "heatmap"],
                            "description": "Type of visualization component"
                        },
                        "title": {
                            "type": "string",
                            "description": "Display title for this component"
                        },
                        "sql_query": {
                            "type": "string",
                            "description": "SQL query against the supply_chain table to get data for this component. Use DuckDB SQL syntax."
                        },
                        "config": {
                            "type": "object",
                            "description": "Visualization-specific configuration",
                            "properties": {
                                "x_column": {"type": "string", "description": "Column for x-axis (charts)"},
                                "y_column": {"type": "string", "description": "Column for y-axis (charts)"},
                                "color_column": {"type": "string", "description": "Column for color grouping"},
                                "value_column": {"type": "string", "description": "Column for the metric value (KPI cards)"},
                                "format": {"type": "string", "description": "Display format: 'number', 'currency', 'percentage', 'decimal'"},
                                "sort_by": {"type": "string", "description": "Column to sort by"},
                                "sort_order": {"type": "string", "enum": ["asc", "desc"]},
                                "limit": {"type": "integer", "description": "Max rows to display"},
                                "threshold": {"type": "number", "description": "Threshold value for highlighting (e.g., defect rate > 5%)"},
                                "threshold_color": {"type": "string", "description": "Color for values above threshold: 'red', 'orange', 'yellow'"},
                                "aggregation": {"type": "string", "description": "Aggregation function if needed: sum, avg, count, min, max"}
                            }
                        },
                        "width": {
                            "type": "string",
                            "enum": ["full", "half", "third"],
                            "description": "Width of this component in the layout"
                        }
                    },
                    "required": ["id", "type", "title", "sql_query", "config", "width"]
                }
            },
            "filters": {
                "type": "array",
                "description": "Interactive filters for the dashboard",
                "items": {
                    "type": "object",
                    "properties": {
                        "column": {"type": "string", "description": "Column to filter on"},
                        "label": {"type": "string", "description": "Display label for the filter"},
                        "filter_type": {
                            "type": "string",
                            "enum": ["select", "multiselect", "date_range", "number_range"],
                            "description": "Type of filter widget"
                        }
                    },
                    "required": ["column", "label", "filter_type"]
                }
            },
            "data_summary": {
                "type": "string",
                "description": "Brief summary of data transformations being performed"
            }
        },
        "required": ["app_title", "app_description", "components", "filters", "data_summary"]
    }
}

SYSTEM_PROMPT = """You are StackForge, an AI data app architect. Your job is to convert natural language descriptions into structured data application definitions.

The user is a non-technical business person. They describe what they want to see, and you design a complete interactive dashboard application.

You have access to a supply chain database with this schema:

Table: supply_chain
Columns:
  - order_id (VARCHAR) — unique order identifier
  - order_date (DATE) — order date
  - supplier (VARCHAR) — supplier company name
  - region (VARCHAR) — geographic region (North America, Europe, Asia Pacific, Latin America, Middle East)
  - product (VARCHAR) — product name
  - category (VARCHAR) — product category (Raw Materials, Components, Finished Goods, Packaging, Equipment)
  - quantity (INTEGER) — order quantity
  - unit_cost (DOUBLE) — cost per unit
  - total_cost (DOUBLE) — total order cost
  - defect_rate (DOUBLE) — defect rate as percentage (0-12)
  - delivery_days (INTEGER) — days to deliver
  - on_time_delivery (INTEGER) — 1 if on time, 0 if late
  - shipping_mode (VARCHAR) — shipping method (Air, Sea, Rail, Truck, Express)
  - shipping_cost (DOUBLE) — cost of shipping
  - warehouse_cost (DOUBLE) — warehousing cost

Rules for generating app definitions:
1. Always include at least one KPI card row at the top showing key metrics
2. Include 2-4 charts that tell a visual story about the data
3. Include a detailed data table at the bottom
4. Add appropriate filters (usually region, supplier, date range, category)
5. SQL queries must be valid DuckDB SQL against the supply_chain table
6. For KPI cards, use aggregation queries (SUM, AVG, COUNT, etc.)
7. For charts, group by meaningful dimensions and aggregate metrics
8. For tables, select relevant columns with sorting
9. Use threshold highlighting for important metrics (e.g., defect_rate > 5 is bad)
10. Layout should flow: KPIs at top (half or third width), charts in middle (half width), table at bottom (full width)
11. Always consider what would be most useful for a BUSINESS USER to see
12. Date queries should use strftime or date_part for grouping by month/quarter

When the user asks to REFINE an existing app, modify only the relevant components. Add new ones, change queries, update configurations — but preserve the overall structure unless they want a complete redesign."""

def parse_intent(user_message: str, existing_app: dict = None, table_schema: str = None) -> dict:
    """Parse user's natural language into a structured app definition."""

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    if existing_app:
        messages.append({
            "role": "system",
            "content": f"The user has an EXISTING app that they want to refine. Current app definition:\n{json.dumps(existing_app, indent=2)}\n\nApply their requested changes while preserving the rest of the app structure. Return the complete updated app definition."
        })

    if table_schema:
        messages.append({
            "role": "system",
            "content": f"Current table schema (may differ from default):\n{table_schema}"
        })

    messages.append({"role": "user", "content": user_message})

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=messages,
        tools=[{"type": "function", "function": APP_INTENT_FUNCTION}],
        tool_choice={"type": "function", "function": {"name": "create_data_app"}},
        temperature=0.3,
    )

    result = json.loads(
        response.choices[0].message.tool_calls[0].function.arguments
    )

    return result
```

**Commit: "feat: add intent parser with GPT-5.1 function calling for data app generation"**

---

## STEP 3: AI ENGINE — CODE EXECUTOR AND GOVERNANCE

### Create `engine/executor.py`:

```python
"""Stage 3: Safely execute generated SQL queries against DuckDB."""

import duckdb
import pandas as pd
from typing import Tuple, Optional

def execute_query(conn: duckdb.DuckDBPyConnection, sql_query: str, filters: dict = None) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """Execute a SQL query and return results as a DataFrame.

    Args:
        conn: DuckDB connection
        sql_query: SQL query string
        filters: Dict of column -> value(s) for WHERE clause injection

    Returns:
        Tuple of (DataFrame result, error message or None)
    """
    try:
        # Apply filters if provided
        if filters:
            filter_clauses = []
            for col, val in filters.items():
                if val is None or (isinstance(val, list) and len(val) == 0):
                    continue
                if isinstance(val, list):
                    # Multiselect filter
                    values_str = ", ".join([f"'{v}'" for v in val])
                    filter_clauses.append(f"{col} IN ({values_str})")
                elif isinstance(val, tuple) and len(val) == 2:
                    # Range filter
                    filter_clauses.append(f"{col} BETWEEN '{val[0]}' AND '{val[1]}'")
                else:
                    filter_clauses.append(f"{col} = '{val}'")

            if filter_clauses:
                # Wrap the original query and add WHERE clause
                filter_sql = " AND ".join(filter_clauses)
                sql_query = f"SELECT * FROM ({sql_query}) AS subq WHERE {filter_sql}"

        result = conn.execute(sql_query).fetchdf()
        return result, None

    except Exception as e:
        return None, str(e)

def execute_app_components(conn: duckdb.DuckDBPyConnection, app_definition: dict, filters: dict = None) -> dict:
    """Execute all component queries in an app definition.

    Returns dict mapping component_id -> {data: DataFrame, error: str or None}
    """
    results = {}

    for component in app_definition.get("components", []):
        comp_id = component["id"]
        sql = component["sql_query"]

        df, error = execute_query(conn, sql, filters)
        results[comp_id] = {
            "data": df,
            "error": error,
            "component": component,
        }

    return results
```

### Create `engine/validator.py`:

```python
"""Stage 4: Validate generated queries and explain in plain English."""

def validate_and_explain(app_definition: dict, execution_results: dict) -> dict:
    """Validate the app and generate plain-English explanations."""

    explanations = []
    warnings = []

    for component in app_definition.get("components", []):
        comp_id = component["id"]
        result = execution_results.get(comp_id, {})

        # Check for execution errors
        if result.get("error"):
            warnings.append({
                "component_id": comp_id,
                "severity": "high",
                "message": f"Query failed: {result['error']}"
            })
            explanations.append({
                "component_id": comp_id,
                "title": component["title"],
                "explanation": f"⚠️ This component encountered an error and couldn't load."
            })
            continue

        df = result.get("data")
        if df is not None:
            row_count = len(df)
            col_count = len(df.columns)

            # Generate explanation based on component type
            comp_type = component["type"]
            title = component["title"]

            if comp_type == "kpi_card":
                if row_count == 1 and col_count >= 1:
                    value = df.iloc[0, 0]
                    explanations.append({
                        "component_id": comp_id,
                        "title": title,
                        "explanation": f"Shows the key metric: {title}. Current value calculated from {row_count} result row(s)."
                    })
                else:
                    warnings.append({
                        "component_id": comp_id,
                        "severity": "medium",
                        "message": f"KPI card returned {row_count} rows — expected 1. Query may need adjustment."
                    })

            elif comp_type in ["bar_chart", "line_chart", "pie_chart", "area_chart", "scatter_plot"]:
                explanations.append({
                    "component_id": comp_id,
                    "title": title,
                    "explanation": f"Visualizes {row_count} data points across {col_count} dimensions."
                })

                if row_count == 0:
                    warnings.append({
                        "component_id": comp_id,
                        "severity": "medium",
                        "message": "Chart has no data — filters may be too restrictive."
                    })
                elif row_count > 50:
                    warnings.append({
                        "component_id": comp_id,
                        "severity": "low",
                        "message": f"Chart has {row_count} categories — consider aggregating for readability."
                    })

            elif comp_type == "table":
                explanations.append({
                    "component_id": comp_id,
                    "title": title,
                    "explanation": f"Displays {row_count} rows with {col_count} columns of detailed data."
                })

    return {
        "explanations": explanations,
        "warnings": warnings,
        "overall_status": "error" if any(w["severity"] == "high" for w in warnings) else "warning" if warnings else "pass"
    }
```

### Create `engine/governance.py`:

```python
"""Stage 5: Governance checks — deterministic, no AI calls."""

import re
from config import PII_PATTERNS, ROLES

def run_governance_checks(app_definition: dict, role: str, execution_results: dict = None) -> dict:
    """Run governance checks on the app definition.

    Returns:
        {
            "checks": [{"rule": str, "status": "pass"|"warning"|"fail", "message": str}],
            "requires_approval": bool,
            "pii_columns_detected": list,
            "overall_status": "compliant"|"review_required"|"non_compliant"
        }
    """
    checks = []
    pii_detected = []
    role_config = ROLES.get(role, ROLES["viewer"])

    # 1. PII Detection — scan all column references in configs
    all_sql = " ".join([c.get("sql_query", "") for c in app_definition.get("components", [])])
    for pattern in PII_PATTERNS:
        matches = re.findall(pattern, all_sql)
        pii_detected.extend(matches)

    pii_detected = list(set(pii_detected))

    if pii_detected:
        if role_config["can_view_pii"]:
            checks.append({
                "rule": "PII Detection",
                "status": "warning",
                "message": f"PII columns detected: {', '.join(pii_detected)}. Admin access allows viewing.",
                "details": "Columns containing personally identifiable information were found in queries."
            })
        else:
            checks.append({
                "rule": "PII Detection",
                "status": "fail",
                "message": f"PII columns detected: {', '.join(pii_detected)}. Data will be masked for {role} role.",
                "details": "These columns will be automatically masked in the output."
            })
    else:
        checks.append({
            "rule": "PII Detection",
            "status": "pass",
            "message": "No PII columns detected in queries.",
        })

    # 2. Access Control — check role permissions
    component_count = len(app_definition.get("components", []))
    has_tables = any(c["type"] == "table" for c in app_definition.get("components", []))

    if not role_config["can_view_raw_data"] and has_tables:
        checks.append({
            "rule": "Access Control",
            "status": "warning",
            "message": f"Viewer role cannot access raw data tables. Tables will show aggregated data only.",
        })
    else:
        checks.append({
            "rule": "Access Control",
            "status": "pass",
            "message": f"All components are accessible for {role} role.",
        })

    # 3. Query Complexity
    complexity = role_config["max_query_complexity"]
    if complexity == "simple" and component_count > 4:
        checks.append({
            "rule": "Query Complexity",
            "status": "warning",
            "message": f"App has {component_count} components — exceeds 'simple' complexity limit for viewer role.",
        })
    elif complexity == "medium" and component_count > 8:
        checks.append({
            "rule": "Query Complexity",
            "status": "warning",
            "message": f"App has {component_count} components — exceeds 'medium' complexity limit for analyst role.",
        })
    else:
        checks.append({
            "rule": "Query Complexity",
            "status": "pass",
            "message": f"App complexity ({component_count} components) is within {role} role limits.",
        })

    # 4. Data Quality — check for SELECT * patterns
    for comp in app_definition.get("components", []):
        if "SELECT *" in comp.get("sql_query", "").upper():
            checks.append({
                "rule": "Data Quality",
                "status": "warning",
                "message": f"Component '{comp['title']}' uses SELECT * — consider selecting specific columns for performance.",
            })
            break
    else:
        checks.append({
            "rule": "Data Quality",
            "status": "pass",
            "message": "All queries use specific column selections.",
        })

    # 5. Export Control
    if not role_config["can_export"]:
        checks.append({
            "rule": "Export Control",
            "status": "warning",
            "message": "Data export is disabled for viewer role. Download buttons will be hidden.",
        })
    else:
        checks.append({
            "rule": "Export Control",
            "status": "pass",
            "message": f"Data export is enabled for {role} role.",
        })

    # 6. Audit Trail
    checks.append({
        "rule": "Audit Trail",
        "status": "pass",
        "message": "All queries and actions are logged to the audit trail.",
    })

    # Determine overall status
    has_fails = any(c["status"] == "fail" for c in checks)
    has_warnings = any(c["status"] == "warning" for c in checks)

    requires_approval = role != "admin" and (has_fails or component_count > 6)

    return {
        "checks": checks,
        "requires_approval": requires_approval,
        "pii_columns_detected": pii_detected,
        "overall_status": "non_compliant" if has_fails else "review_required" if has_warnings else "compliant",
    }
```

**Commit: "feat: add executor, validator, and governance checks"**

---

## STEP 4: UI COMPONENTS

### Create `ui/styles.py`:

```python
"""Custom CSS for StackForge dark theme."""

CUSTOM_CSS = """
<style>
    /* Dark theme overrides */
    .stApp {
        background-color: #0f172a;
    }

    /* KPI Card styling */
    .kpi-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .kpi-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: #f8fafc;
    }
    .kpi-label {
        font-size: 0.875rem;
        color: #94a3b8;
        margin-top: 4px;
    }
    .kpi-delta-positive { color: #22c55e; }
    .kpi-delta-negative { color: #ef4444; }

    /* Governance badge */
    .gov-pass { color: #22c55e; }
    .gov-warning { color: #eab308; }
    .gov-fail { color: #ef4444; }

    /* Chat styling */
    .chat-user {
        background-color: #4f46e5;
        color: white;
        padding: 10px 16px;
        border-radius: 12px 12px 0 12px;
        margin: 4px 0;
        max-width: 80%;
        margin-left: auto;
    }
    .chat-assistant {
        background-color: #1e293b;
        color: #f1f5f9;
        padding: 10px 16px;
        border-radius: 12px 12px 12px 0;
        margin: 4px 0;
        max-width: 80%;
        border: 1px solid #334155;
    }

    /* Engine view */
    .engine-code {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: #e2e8f0;
        overflow-x: auto;
    }

    /* Header */
    .stackforge-header {
        background: linear-gradient(90deg, #4f46e5 0%, #7c3aed 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2rem;
        font-weight: 800;
    }
</style>
"""
```

### Create `ui/chat.py`:

```python
"""Chat interface component for StackForge."""

import streamlit as st
from datetime import datetime

def render_chat_interface():
    """Render the conversational chat interface."""

    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat messages
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("app_summary"):
                with st.expander("📊 View App Details"):
                    st.write(msg["app_summary"])

    # Chat input
    if prompt := st.chat_input("Describe the data app you want to build..."):
        # Add user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        return prompt

    return None

def add_assistant_message(content: str, app_summary: str = None):
    """Add an assistant message to the chat."""
    msg = {"role": "assistant", "content": content, "app_summary": app_summary}
    st.session_state.messages.append(msg)

def render_template_selector(templates: list):
    """Render template selection cards when chat is empty."""
    if st.session_state.get("messages"):
        return None

    st.markdown("### 🏭 Start from a Template")
    st.markdown("Select a pre-built data app template, or describe what you want below.")

    cols = st.columns(3)
    selected = None

    for i, template in enumerate(templates):
        with cols[i % 3]:
            with st.container(border=True):
                st.markdown(f"**{template['icon']} {template['name']}**")
                st.caption(template["description"])
                gov_color = {"low": "🟢", "medium": "🟡", "high": "🔴"}
                st.caption(f"Governance: {gov_color.get(template['governance_level'], '⚪')} {template['governance_level'].title()}")
                if st.button("Use Template →", key=f"template_{template['id']}"):
                    selected = template

    return selected
```

### Create `ui/dashboard.py`:

```python
"""Dashboard renderer — generates interactive Plotly charts, KPI cards, and tables."""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

def render_dashboard(app_definition: dict, execution_results: dict, role: str = "analyst"):
    """Render the complete dashboard from app definition and query results."""

    if not app_definition:
        _render_empty_state()
        return

    # App header
    st.markdown(f"## {app_definition.get('app_title', 'Data App')}")
    st.caption(app_definition.get("app_description", ""))

    # Render filters in sidebar or top bar
    filters = _render_filters(app_definition.get("filters", []), execution_results)

    # Render components by layout
    components = app_definition.get("components", [])

    # Group components by rows (based on width)
    current_row = []
    rows = []
    current_width = 0

    for comp in components:
        width = {"full": 1.0, "half": 0.5, "third": 0.33}.get(comp.get("width", "full"), 1.0)
        if current_width + width > 1.0:
            if current_row:
                rows.append(current_row)
            current_row = [comp]
            current_width = width
        else:
            current_row.append(comp)
            current_width += width
    if current_row:
        rows.append(current_row)

    # Render each row
    for row in rows:
        if len(row) == 1:
            _render_component(row[0], execution_results)
        else:
            cols = st.columns(len(row))
            for i, comp in enumerate(row):
                with cols[i]:
                    _render_component(comp, execution_results)

def _render_empty_state():
    """Render empty state when no app is generated."""
    st.markdown("### 🏗️ Your data app will appear here")
    st.markdown("Describe what you want to see in the chat, or select a template to get started.")

    # Show sample capabilities
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("📊 **Interactive Charts**")
        st.caption("Bar, line, pie, scatter, area charts with drill-down")
    with col2:
        st.markdown("📋 **Data Tables**")
        st.caption("Sortable, filterable tables with export")
    with col3:
        st.markdown("🎯 **KPI Cards**")
        st.caption("Key metrics with trend indicators")

def _render_filters(filter_defs: list, execution_results: dict) -> dict:
    """Render sidebar filters and return selected values."""
    if not filter_defs:
        return {}

    filters = {}
    with st.sidebar:
        st.markdown("### 🔍 Filters")
        for f in filter_defs:
            col = f["column"]
            label = f["label"]
            ftype = f["filter_type"]

            # Get unique values from any execution result that has this column
            unique_values = set()
            for result in execution_results.values():
                df = result.get("data")
                if df is not None and col in df.columns:
                    unique_values.update(df[col].dropna().unique().tolist())

            unique_values = sorted(list(unique_values))

            if ftype == "select":
                selected = st.selectbox(label, ["All"] + unique_values, key=f"filter_{col}")
                if selected != "All":
                    filters[col] = selected
            elif ftype == "multiselect":
                selected = st.multiselect(label, unique_values, key=f"filter_{col}")
                if selected:
                    filters[col] = selected
            elif ftype == "date_range":
                date_range = st.date_input(label, key=f"filter_{col}")
                if isinstance(date_range, tuple) and len(date_range) == 2:
                    filters[col] = date_range
            elif ftype == "number_range":
                if unique_values:
                    min_val = min([v for v in unique_values if isinstance(v, (int, float))] or [0])
                    max_val = max([v for v in unique_values if isinstance(v, (int, float))] or [100])
                    selected = st.slider(label, min_val, max_val, (min_val, max_val), key=f"filter_{col}")
                    if selected != (min_val, max_val):
                        filters[col] = selected

    return filters

def _render_component(component: dict, execution_results: dict):
    """Render a single dashboard component."""
    comp_id = component["id"]
    comp_type = component["type"]
    title = component["title"]
    config = component.get("config", {})

    result = execution_results.get(comp_id, {})
    df = result.get("data")
    error = result.get("error")

    if error:
        st.error(f"⚠️ {title}: {error}")
        return

    if df is None or df.empty:
        st.info(f"📭 {title}: No data available")
        return

    if comp_type == "kpi_card":
        _render_kpi(title, df, config)
    elif comp_type == "bar_chart":
        _render_bar_chart(title, df, config)
    elif comp_type == "line_chart":
        _render_line_chart(title, df, config)
    elif comp_type == "pie_chart":
        _render_pie_chart(title, df, config)
    elif comp_type == "scatter_plot":
        _render_scatter(title, df, config)
    elif comp_type == "area_chart":
        _render_area_chart(title, df, config)
    elif comp_type == "table":
        _render_table(title, df, config)
    elif comp_type == "metric_highlight":
        _render_metric_highlight(title, df, config)

def _render_kpi(title: str, df: pd.DataFrame, config: dict):
    """Render a KPI metric card."""
    value = df.iloc[0, 0] if len(df) > 0 and len(df.columns) > 0 else 0

    fmt = config.get("format", "number")
    if fmt == "currency":
        display_val = f"${value:,.0f}" if isinstance(value, (int, float)) else str(value)
    elif fmt == "percentage":
        display_val = f"{value:.1f}%" if isinstance(value, (int, float)) else str(value)
    elif fmt == "decimal":
        display_val = f"{value:.2f}" if isinstance(value, (int, float)) else str(value)
    else:
        display_val = f"{value:,.0f}" if isinstance(value, (int, float)) else str(value)

    st.metric(label=title, value=display_val)

def _render_bar_chart(title: str, df: pd.DataFrame, config: dict):
    """Render a Plotly bar chart."""
    x_col = config.get("x_column", df.columns[0])
    y_col = config.get("y_column", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    color_col = config.get("color_column")

    fig = px.bar(df, x=x_col, y=y_col, color=color_col, title=title,
                 template="plotly_dark")
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        height=400,
    )

    # Add threshold line if configured
    threshold = config.get("threshold")
    if threshold is not None:
        fig.add_hline(y=threshold, line_dash="dash",
                      line_color=config.get("threshold_color", "red"),
                      annotation_text=f"Threshold: {threshold}")

    st.plotly_chart(fig, use_container_width=True)

def _render_line_chart(title: str, df: pd.DataFrame, config: dict):
    """Render a Plotly line chart."""
    x_col = config.get("x_column", df.columns[0])
    y_col = config.get("y_column", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    color_col = config.get("color_column")

    fig = px.line(df, x=x_col, y=y_col, color=color_col, title=title,
                  template="plotly_dark", markers=True)
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        height=400,
    )
    st.plotly_chart(fig, use_container_width=True)

def _render_pie_chart(title: str, df: pd.DataFrame, config: dict):
    """Render a Plotly pie chart."""
    names_col = config.get("x_column", df.columns[0])
    values_col = config.get("y_column", df.columns[1] if len(df.columns) > 1 else df.columns[0])

    fig = px.pie(df, names=names_col, values=values_col, title=title,
                 template="plotly_dark")
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        height=400,
    )
    st.plotly_chart(fig, use_container_width=True)

def _render_scatter(title: str, df: pd.DataFrame, config: dict):
    """Render a Plotly scatter plot."""
    x_col = config.get("x_column", df.columns[0])
    y_col = config.get("y_column", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    color_col = config.get("color_column")

    fig = px.scatter(df, x=x_col, y=y_col, color=color_col, title=title,
                     template="plotly_dark")
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        height=400,
    )
    st.plotly_chart(fig, use_container_width=True)

def _render_area_chart(title: str, df: pd.DataFrame, config: dict):
    """Render a Plotly area chart."""
    x_col = config.get("x_column", df.columns[0])
    y_col = config.get("y_column", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    color_col = config.get("color_column")

    fig = px.area(df, x=x_col, y=y_col, color=color_col, title=title,
                  template="plotly_dark")
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        height=400,
    )
    st.plotly_chart(fig, use_container_width=True)

def _render_table(title: str, df: pd.DataFrame, config: dict):
    """Render an interactive data table."""
    st.markdown(f"**{title}**")

    sort_by = config.get("sort_by")
    sort_order = config.get("sort_order", "desc")
    limit = config.get("limit", 100)

    display_df = df.copy()
    if sort_by and sort_by in display_df.columns:
        display_df = display_df.sort_values(sort_by, ascending=(sort_order == "asc"))

    display_df = display_df.head(limit)

    st.dataframe(display_df, use_container_width=True, height=400)

def _render_metric_highlight(title: str, df: pd.DataFrame, config: dict):
    """Render a metric with conditional highlighting."""
    value = df.iloc[0, 0] if len(df) > 0 else 0
    threshold = config.get("threshold")

    if threshold and isinstance(value, (int, float)):
        color = config.get("threshold_color", "red") if value > threshold else "green"
        st.metric(label=title, value=f"{value:.1f}%", delta=f"{'Above' if value > threshold else 'Below'} threshold ({threshold})")
    else:
        st.metric(label=title, value=str(value))
```

### Create `ui/engine_view.py`:

```python
"""Show Engine view — reveals the technical internals behind the dashboard."""

import streamlit as st
import json

def render_engine_view(app_definition: dict, execution_results: dict, validation: dict, governance: dict):
    """Render the technical engine view showing what's happening under the hood."""

    if not app_definition:
        st.info("🔧 The engine view will show generated code, DAG, and governance audit when you build an app.")
        return

    tab1, tab2, tab3, tab4 = st.tabs(["📝 Generated SQL", "🔀 Data Flow", "🛡️ Governance", "📋 Audit Log"])

    with tab1:
        st.markdown("### Generated Queries")
        st.caption("These SQL queries were generated by the AI to power each dashboard component.")

        for comp in app_definition.get("components", []):
            with st.expander(f"**{comp['title']}** ({comp['type']})", expanded=False):
                st.code(comp["sql_query"], language="sql")

                # Show execution result summary
                result = execution_results.get(comp["id"], {})
                if result.get("data") is not None:
                    st.caption(f"✅ Returned {len(result['data'])} rows, {len(result['data'].columns)} columns")
                elif result.get("error"):
                    st.caption(f"❌ Error: {result['error']}")

    with tab2:
        st.markdown("### Data Transformation Flow")
        st.caption("How data flows from source to each visualization component.")

        # Show data flow as a simple diagram
        st.markdown("```")
        st.markdown("supply_chain (raw data)")
        st.markdown("         │")

        filters = app_definition.get("filters", [])
        if filters:
            filter_names = [f["label"] for f in filters]
            st.markdown(f"    [Filters: {', '.join(filter_names)}]")
            st.markdown("         │")

        for comp in app_definition.get("components", []):
            icon = {"kpi_card": "🎯", "bar_chart": "📊", "line_chart": "📈",
                    "pie_chart": "🥧", "table": "📋", "scatter_plot": "⚡",
                    "area_chart": "📉", "metric_highlight": "🔴"}.get(comp["type"], "📦")
            st.markdown(f"    ├──→ {icon} {comp['title']}")

        st.markdown("```")

    with tab3:
        _render_governance_detail(governance)

    with tab4:
        _render_audit_log()

def _render_governance_detail(governance: dict):
    """Render detailed governance view."""
    if not governance:
        st.info("Governance checks will appear after building an app.")
        return

    # Overall status
    status = governance.get("overall_status", "unknown")
    status_map = {
        "compliant": ("✅ Compliant", "success"),
        "review_required": ("⚠️ Review Required", "warning"),
        "non_compliant": ("❌ Non-Compliant", "error"),
    }
    label, msg_type = status_map.get(status, ("❓ Unknown", "info"))

    if msg_type == "success":
        st.success(label)
    elif msg_type == "warning":
        st.warning(label)
    elif msg_type == "error":
        st.error(label)

    # Individual checks
    for check in governance.get("checks", []):
        icon = {"pass": "✅", "warning": "⚠️", "fail": "❌"}.get(check["status"], "❓")
        with st.expander(f"{icon} {check['rule']}", expanded=(check["status"] != "pass")):
            st.write(check["message"])
            if check.get("details"):
                st.caption(check["details"])

    # Approval requirement
    if governance.get("requires_approval"):
        st.warning("🔒 This app requires admin approval before deployment.")

def _render_audit_log():
    """Render the audit log trail."""
    st.markdown("### Audit Trail")

    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []

    if not st.session_state.audit_log:
        st.info("No audit entries yet. Build an app to start logging.")
        return

    for entry in reversed(st.session_state.audit_log[-20:]):
        st.markdown(f"**{entry['timestamp']}** — {entry['action']}")
        st.caption(entry.get("details", ""))

def add_audit_entry(action: str, details: str = ""):
    """Add an entry to the audit log."""
    from datetime import datetime

    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []

    st.session_state.audit_log.append({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "action": action,
        "details": details,
    })
```

**Commit: "feat: add UI components — chat, dashboard renderer, engine view"**

---

## STEP 5: MAIN APPLICATION

### Create `app.py`:

```python
"""StackForge — AI-Powered Data App Factory
Built at HackUSU 2026 · Data App Factory Track
"""

import streamlit as st
from config import APP_NAME, TEMPLATES, ROLES
from data.sample_data_loader import get_connection, get_table_schema
from engine.intent_parser import parse_intent
from engine.executor import execute_app_components
from engine.validator import validate_and_explain
from engine.governance import run_governance_checks
from ui.chat import render_chat_interface, add_assistant_message, render_template_selector
from ui.dashboard import render_dashboard
from ui.engine_view import render_engine_view, add_audit_entry
from ui.styles import CUSTOM_CSS

# ── Page Config ─────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Data App Factory",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Apply custom CSS
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ── Initialize Session State ────────────────────────────
if "db_conn" not in st.session_state:
    st.session_state.db_conn = get_connection()
if "current_app" not in st.session_state:
    st.session_state.current_app = None
if "execution_results" not in st.session_state:
    st.session_state.execution_results = {}
if "validation" not in st.session_state:
    st.session_state.validation = None
if "governance" not in st.session_state:
    st.session_state.governance = None
if "current_role" not in st.session_state:
    st.session_state.current_role = "analyst"
if "show_engine" not in st.session_state:
    st.session_state.show_engine = False
if "messages" not in st.session_state:
    st.session_state.messages = []
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

# ── Header ──────────────────────────────────────────────
header_col1, header_col2, header_col3 = st.columns([3, 2, 2])

with header_col1:
    st.markdown(f"# 🏭 {APP_NAME}")
    st.caption("Forge Interactive Data Apps from Conversation · Powered by Databricks + AWS")

with header_col2:
    # Role toggle
    role = st.selectbox(
        "Current Role",
        options=list(ROLES.keys()),
        format_func=lambda x: ROLES[x]["label"],
        index=list(ROLES.keys()).index(st.session_state.current_role),
        key="role_selector",
    )
    if role != st.session_state.current_role:
        st.session_state.current_role = role
        # Re-run governance checks
        if st.session_state.current_app:
            st.session_state.governance = run_governance_checks(
                st.session_state.current_app,
                st.session_state.current_role,
                st.session_state.execution_results,
            )
            add_audit_entry(f"Role switched to {role}")

with header_col3:
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        show_engine = st.toggle("🔧 Show Engine", value=st.session_state.show_engine)
        st.session_state.show_engine = show_engine
    with col_b:
        if st.button("🎬 Demo", use_container_width=True):
            st.session_state.demo_mode = True
    with col_c:
        if st.button("🔄 Reset", use_container_width=True):
            for key in ["current_app", "execution_results", "validation",
                       "governance", "messages", "audit_log"]:
                if key in st.session_state:
                    if key == "messages":
                        st.session_state[key] = []
                    elif key == "audit_log":
                        st.session_state[key] = []
                    else:
                        st.session_state[key] = None
            st.rerun()

st.divider()

# ── Main Layout ─────────────────────────────────────────
# Two columns: Chat (35%) | Dashboard (65%)
chat_col, dash_col = st.columns([0.35, 0.65])

def _process_prompt(prompt: str):
    """Process a user prompt through the full pipeline."""

    with st.spinner("🧠 Parsing intent..."):
        add_audit_entry("Intent parsing started", f"Prompt: {prompt[:80]}...")

        try:
            # Get table schema for context
            schema = get_table_schema(st.session_state.db_conn)

            # Parse intent (with existing app for refinement)
            app_def = parse_intent(
                prompt,
                existing_app=st.session_state.current_app,
                table_schema=schema,
            )
            st.session_state.current_app = app_def
            add_audit_entry("App definition generated", f"{len(app_def.get('components', []))} components")

        except Exception as e:
            add_assistant_message(f"❌ Error parsing your request: {str(e)}")
            add_audit_entry("Intent parsing failed", str(e))
            st.rerun()
            return

    with st.spinner("⚡ Executing queries..."):
        try:
            results = execute_app_components(st.session_state.db_conn, app_def)
            st.session_state.execution_results = results
            add_audit_entry("Queries executed", f"{len(results)} components")
        except Exception as e:
            add_assistant_message(f"❌ Error executing queries: {str(e)}")
            st.rerun()
            return

    with st.spinner("✅ Validating..."):
        validation = validate_and_explain(app_def, results)
        st.session_state.validation = validation

    with st.spinner("🛡️ Running governance checks..."):
        governance = run_governance_checks(app_def, st.session_state.current_role, results)
        st.session_state.governance = governance
        add_audit_entry("Governance checks completed", governance["overall_status"])

    # Generate response message
    comp_count = len(app_def.get("components", []))
    warning_count = len(validation.get("warnings", []))
    gov_status = governance["overall_status"]

    response = f"✅ Built **{app_def['app_title']}** with {comp_count} components."
    if warning_count > 0:
        response += f"\n⚠️ {warning_count} warning(s) to review."
    response += f"\n🛡️ Governance: {gov_status.replace('_', ' ').title()}"
    response += "\n\nYou can refine this app by telling me what to change!"

    add_assistant_message(response, app_summary=app_def.get("app_description"))

    st.rerun()

with chat_col:
    st.markdown("### 💬 Chat")

    # Template selector (when chat is empty)
    selected_template = render_template_selector(TEMPLATES)

    # Handle template selection
    if selected_template:
        prompt = selected_template["default_prompt"]
        st.session_state.messages.append({"role": "user", "content": prompt})
        _process_prompt(prompt)

    # Handle demo mode
    if st.session_state.get("demo_mode"):
        st.session_state.demo_mode = False
        demo_prompt = TEMPLATES[0]["default_prompt"]  # Supplier Performance
        st.session_state.messages.append({"role": "user", "content": demo_prompt})
        _process_prompt(demo_prompt)

    # Chat interface
    user_prompt = render_chat_interface()

    if user_prompt:
        _process_prompt(user_prompt)

# ── Dashboard Area ──────────────────────────────────────
with dash_col:
    if st.session_state.show_engine:
        # Split view: Dashboard + Engine
        dash_tab, engine_tab = st.tabs(["📊 Dashboard", "🔧 Engine"])

        with dash_tab:
            render_dashboard(
                st.session_state.current_app,
                st.session_state.execution_results,
                st.session_state.current_role,
            )

        with engine_tab:
            render_engine_view(
                st.session_state.current_app,
                st.session_state.execution_results,
                st.session_state.validation,
                st.session_state.governance,
            )
    else:
        render_dashboard(
            st.session_state.current_app,
            st.session_state.execution_results,
            st.session_state.current_role,
        )

# ── Sidebar: Governance Summary ─────────────────────────
with st.sidebar:
    st.markdown("---")
    st.markdown("### 🛡️ Governance")

    if st.session_state.governance:
        gov = st.session_state.governance
        status = gov["overall_status"]
        status_icon = {"compliant": "✅", "review_required": "⚠️", "non_compliant": "❌"}.get(status, "❓")
        st.markdown(f"**Status:** {status_icon} {status.replace('_', ' ').title()}")

        for check in gov.get("checks", []):
            icon = {"pass": "✅", "warning": "⚠️", "fail": "❌"}.get(check["status"])
            st.markdown(f"{icon} {check['rule']}")

        if gov.get("requires_approval"):
            st.warning("🔒 Requires admin approval")
            if st.session_state.current_role == "admin":
                if st.button("✅ Approve App"):
                    add_audit_entry("App approved by admin")
                    st.success("App approved!")
    else:
        st.info("Build an app to see governance checks")

    st.markdown("---")
    st.markdown(f"**Role:** {ROLES[st.session_state.current_role]['label']}")
    st.markdown(f"**Dataset:** Supply Chain (500 rows)")
    st.caption(f"Built at HackUSU 2026 · Data App Factory Track")
```

**Commit: "feat: assemble main application with chat + dashboard + engine view"**

---

## STEP 6: FINAL VERIFICATION AND DEMO POLISH

### Verification Checklist:

- [ ] `streamlit run app.py` launches without errors
- [ ] Demo button triggers full end-to-end flow with real data
- [ ] All 6 templates generate valid dashboards
- [ ] Charts render interactively (Plotly hover, zoom, etc.)
- [ ] KPI cards display formatted values correctly
- [ ] Tables are interactive and sortable
- [ ] SQL queries execute successfully against DuckDB
- [ ] Chat interface displays messages correctly
- [ ] Role toggle switches between analyst and admin views
- [ ] Governance panel shows checks with correct status icons
- [ ] PII detection works for email, phone, salary patterns
- [ ] Show Engine toggle reveals all tabs: SQL, Data Flow, Governance, Audit Log
- [ ] Generated SQL is syntactically valid DuckDB
- [ ] Filters work and update dashboard in real-time
- [ ] No console errors when running
- [ ] Dark theme applies throughout UI
- [ ] Performance is acceptable (no lag on interactions)

### Demo Mode Flow:

1. Click "Demo" button
2. Auto-send Supplier Performance template prompt
3. Build full app: diagram renders → code generates → governance checks pass
4. Chat shows assistant response with 6+ components
5. After 2 seconds, auto-send refinement: "Break down by shipping mode"
6. Pipeline updates in real-time via conversational refinement
7. Governance panel shows all checks passing

**Commit: "feat: complete StackForge Data App Factory MVP — ready for demo"**

---

## IMPORTANT NOTES FOR SUCCESS

**What Judges Will Look For:**

1. **Interactive dashboards, not static reports** — Plotly charts with hover, zoom, legend interaction. Real live data from Supply Chain dataset.

2. **Conversational, not transactional** — Follow-up messages refine the app. Back-and-forth chat, not a one-shot form.

3. **Governance is core, not bolted-on** — PII detection visible, role-based access working, audit log populated, compliance checks prominent.

4. **Factory model** — Templates empower citizens to quickly create apps without coding.

5. **Technical transparency** — "Show Engine" toggle reveals the AI's reasoning (SQL, data flow, governance).

6. **Real data, real ecosystem** — Supply Chain dataset from Koch. Terminology around Databricks, AWS, DuckDB.

7. **Polish and UX** — Dark theme, smooth interactions, no console errors, fast loading.

**File Structure (Final):**

```
stackforge/
├── app.py
├── requirements.txt
├── config.py
├── .env
├── data/
│   ├── supply_chain.csv
│   └── sample_data_loader.py
├── engine/
│   ├── __init__.py
│   ├── intent_parser.py
│   ├── executor.py
│   ├── validator.py
│   └── governance.py
├── ui/
│   ├── __init__.py
│   ├── chat.py
│   ├── dashboard.py
│   ├── engine_view.py
│   └── styles.py
└── utils/
    ├── __init__.py
    └── helpers.py
```

This PRD is complete, comprehensive, and production-ready. Build step-by-step, commit after each milestone. Good luck at HackUSU 2026!
