# PERSON 1 — THE ENGINE
## StackForge AI Data App Factory | HackUSU 2026 (19-hour hackathon)

---

## SECTION 1: CLAUDE CODE KICKOFF PROMPT

**Copy and paste this entire section into your Claude Code instance to start:**

---

### CLAUDE CODE SESSION KICKOFF

You are supporting Person 1 of the StackForge team at HackUSU 2026. The project is a **19-hour hackathon** with a 3-person team.

**YOUR ASSIGNMENT:**
You are building the **ENGINE LAYER** of StackForge — an AI Data App Factory that uses Claude/GPT-5.1 to convert natural language queries into interactive data dashboards. You own the core AI and data processing pipeline.

**FILES YOU OWN:**
- `engine/intent_parser.py` — Parses user intent into an app_definition JSON structure using GPT-5.1 function calling
- `engine/executor.py` — Executes SQL queries against the DuckDB database and aggregates results
- `engine/validator.py` — Validates execution results and generates plain-English explanations
- `data/sample_data_loader.py` — Manages DuckDB connection, loads supply chain data, serves dynamic schema
- `config.py` — Configuration, API keys, PII patterns, roles, and templates

**FILES YOU TOUCH BUT DON'T OWN:**
- `engine/governance.py` — You create a complete working skeleton here. **Person 3 owns deepening this** but it must be functional and integrated.

**FILES YOU DO NOT TOUCH:**
- Anything in `ui/` folder — **Person 2 owns the Streamlit UI entirely**

**THE CONTRACT:**
The `app_definition` JSON is the interface between your engine and Person 2's UI. It must match the schema exactly (defined in SECTION 3 of your PRD). Person 2 will receive this JSON and render it. Person 3 will consume it for governance checks.

**YOUR TECH STACK:**
- **LLM:** GPT-5.1 with function calling (forced tool_choice to `create_data_app`)
- **Database:** DuckDB (embedded, in-memory with CSV fallback)
- **Dataset:** Supply chain data (500 rows: order_id, supplier, region, product, category, shipping_mode, costs, delivery metrics, defect_rate)
- **Language:** Python 3.10+
- **Dependencies:** openai, duckdb, pandas, python-dotenv, pydantic

**YOUR DELIVERABLES:**
1. All engine layer files with complete, working code
2. `app_definition` JSON output that matches the contract schema
3. Dynamic schema injection (schema and sample rows passed to GPT-5.1 at runtime, NOT hardcoded)
4. Support for conversational refinement (modifying existing apps, not rebuilding)
5. Validation and error explanations for Person 2's UI
6. Governance skeleton that Person 3 can extend

**FOLLOW THE PRD BELOW EXACTLY.** Every code file, schema, test case, and timeline item is your spec. You have 19 hours.

---

## SECTION 2: THE PRD FOR PERSON 1

### 2.1 PROJECT SETUP (Hour 0-1)

#### 2.1.1 Directory Structure

```
StackForge/
├── README.md
├── .env                          (template, Person 1 fills this)
├── .gitignore                    (standard Python)
├── requirements.txt              (Person 1 specifies all deps)
├── config.py                     (Person 1: Core configuration)
├── app.py                        (Person 2: Streamlit main app — DO NOT TOUCH)
├── data/
│   └── sample_data_loader.py     (Person 1: DuckDB + sample data)
├── engine/
│   ├── intent_parser.py          (Person 1: Intent → app_definition)
│   ├── executor.py               (Person 1: SQL execution + filtering)
│   ├── validator.py              (Person 1: Validation + explanations)
│   └── governance.py             (Person 1: Skeleton; Person 3 extends)
├── ui/                           (PERSON 2 ONLY — DO NOT TOUCH)
│   ├── chat.py
│   ├── dashboard.py
│   ├── engine_view.py
│   └── styles.py
├── tests/
│   ├── test_intent_parser.py
│   ├── test_executor.py
│   ├── test_validator.py
│   └── test_integration.py
└── docs/
    └── APP_DEFINITION_SCHEMA.md  (contract; auto-generated or manual)
```

**Note:** Person 2 creates and owns `app.py` (Streamlit) and everything in `ui/`. Person 1 creates engine layer. Person 3 owns `governance.py` deepening (but Person 1 ships skeleton). **We are using Streamlit, NOT FastAPI/React.**

---

#### 2.1.2 `requirements.txt`

```
openai==1.50.0
duckdb==1.2.0
pandas==2.2.0
python-dotenv==1.0.0
pydantic==2.5.0
streamlit==1.40.0
plotly==5.24.0
numpy==1.26.0
requests==2.32.0
```

---

#### 2.1.3 `.env` Template

Create `.env` file (not in git):
```
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-5.1
APP_NAME=StackForge
DEBUG=False
LOG_LEVEL=INFO
DATABASE_TYPE=duckdb
DATABASE_PATH=:memory:
DATA_SOURCE=synthetic
```

---

#### 2.1.4 `.gitignore`

```
# Environment
.env
.env.local
.env.*.local

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Logs
*.log
logs/

# Database
*.db
*.duckdb
*.sqlite3

# Testing
.pytest_cache/
.coverage
htmlcov/

# Node (for UI team)
node_modules/
dist/
build/
.next/
```

---

### 2.2 `config.py` — Full Code

```python
import os
from typing import Dict, List, Any
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# API & MODEL CONFIGURATION
# ============================================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.1")
APP_NAME = os.getenv("APP_NAME", "StackForge")
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

DATABASE_TYPE = os.getenv("DATABASE_TYPE", "duckdb")
DATABASE_PATH = os.getenv("DATABASE_PATH", ":memory:")
DATA_SOURCE = os.getenv("DATA_SOURCE", "synthetic")

# ============================================================================
# PII PATTERNS (for governance scanning)
# ============================================================================

PII_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "passport": r"\b[A-Z]{2}\d{6,8}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# ============================================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================================

ROLES = {
    "admin": {
        "display_name": "Administrator",
        "capabilities": [
            "view_all_data",
            "export_data",
            "create_app",
            "modify_app",
            "delete_app",
            "view_pii",
            "audit_trail",
        ],
        "max_rows_per_query": None,  # No limit
    },
    "analyst": {
        "display_name": "Data Analyst",
        "capabilities": [
            "view_all_data",
            "export_data",
            "create_app",
            "modify_app",
        ],
        "max_rows_per_query": 100000,
    },
    "viewer": {
        "display_name": "Viewer",
        "capabilities": [
            "view_all_data",
        ],
        "max_rows_per_query": 10000,
    },
}

# ============================================================================
# APPLICATION TEMPLATES
# ============================================================================

TEMPLATES = [
    {
        "id": "supplier_performance",
        "name": "Supplier Performance",
        "description": "Analyze supplier defect rates and delivery performance",
        "default_prompt": "Create a dashboard showing supplier defect rates by region with on-time delivery percentage",
        "template_components": [
            "bar_chart",  # Defect rate by supplier
            "metric_highlight",  # Average defect rate
            "line_chart",  # Delivery performance trend
        ],
    },
    {
        "id": "regional_analysis",
        "name": "Regional Analysis",
        "description": "Compare regional supply chain metrics",
        "default_prompt": "Show me cost breakdown and order volumes by region with a heat map",
        "template_components": [
            "pie_chart",  # Cost distribution
            "bar_chart",  # Order volume by region
            "metric_highlight",  # Total cost
        ],
    },
    {
        "id": "product_profitability",
        "name": "Product Profitability",
        "description": "Analyze product margins and costs",
        "default_prompt": "Display product margins, unit costs, and order volumes by category",
        "template_components": [
            "scatter_plot",  # Cost vs. volume
            "bar_chart",  # Margin by product
            "table",  # Top products by revenue
        ],
    },
    {
        "id": "shipping_optimization",
        "name": "Shipping Optimization",
        "description": "Optimize shipping costs and delivery performance",
        "default_prompt": "Compare shipping modes by cost, delivery time, and on-time performance",
        "template_components": [
            "bar_chart",  # Cost by shipping mode
            "line_chart",  # Delivery days trend
            "metric_highlight",  # Shipping efficiency score
        ],
    },
    {
        "id": "inventory_health",
        "name": "Inventory Health",
        "description": "Monitor inventory levels and turnover",
        "default_prompt": "Show inventory turnover, warehouse costs, and stock levels by category",
        "template_components": [
            "area_chart",  # Inventory trend
            "bar_chart",  # Warehouse cost by region
            "table",  # Stock status
        ],
    },
    {
        "id": "quality_assurance",
        "name": "Quality Assurance",
        "description": "Monitor product quality and defect trends",
        "default_prompt": "Display defect rates by supplier and product with trend analysis",
        "template_components": [
            "line_chart",  # Defect rate trend
            "bar_chart",  # Defect by supplier
            "metric_highlight",  # Average defect rate
        ],
    },
]

# ============================================================================
# COMPONENT TYPES & CONFIGURATION OPTIONS
# ============================================================================

COMPONENT_TYPES = [
    "kpi_card",
    "bar_chart",
    "line_chart",
    "pie_chart",
    "scatter_plot",
    "table",
    "metric_highlight",
    "area_chart",
]

# ============================================================================
# QUERY LIMITS & CONSTRAINTS
# ============================================================================

MAX_QUERY_COMPLEXITY = 5  # Max number of joins
MAX_RESULT_ROWS = 10000
MAX_COMPONENTS_PER_APP = 8
MIN_CHART_DATA_POINTS = 2
MAX_CHART_CATEGORIES = 50

# ============================================================================
# EXPORT SETTINGS
# ============================================================================

EXPORT_FORMATS = ["csv", "json", "pdf"]
EXPORT_ROW_LIMIT = 50000

# ============================================================================
# VALIDATION RULES
# ============================================================================

VALIDATION_RULES = {
    "table": {
        "min_rows": 1,
        "max_rows": 1000,
        "max_columns": 20,
    },
    "bar_chart": {
        "min_categories": 2,
        "max_categories": 50,
        "min_values": 1,
    },
    "line_chart": {
        "min_points": 3,
        "max_points": 500,
    },
    "pie_chart": {
        "min_slices": 2,
        "max_slices": 12,
    },
    "scatter_plot": {
        "min_points": 3,
        "max_points": 1000,
    },
    "area_chart": {
        "min_points": 3,
        "max_points": 500,
    },
    "kpi_card": {
        "expected_rows": 1,
    },
    "metric_highlight": {
        "expected_rows": 1,
    },
}
```

---

### 2.3 `data/sample_data_loader.py` — Full Code

```python
import duckdb
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Optional, Tuple

# ============================================================================
# GLOBAL CONNECTION (singleton pattern)
# ============================================================================

_conn: Optional[duckdb.DuckDBPyConnection] = None


def get_connection() -> duckdb.DuckDBPyConnection:
    """
    Returns a DuckDB connection. Creates and initializes tables on first call.
    Uses in-memory database (:memory:) for the hackathon.
    """
    global _conn
    if _conn is None:
        _conn = duckdb.connect(":memory:")
        _initialize_tables(_conn)
    return _conn


def _initialize_tables(conn: duckdb.DuckDBPyConnection) -> None:
    """Initialize sample data tables in DuckDB."""
    df = _generate_sample_data()
    conn.register("supply_chain", df)
    print(f"✓ Loaded {len(df)} rows into supply_chain table")


def _generate_sample_data() -> pd.DataFrame:
    """
    Generate 500 rows of synthetic supply chain data.

    Columns:
    - order_id: unique identifier
    - order_date: date of order
    - supplier: supplier name
    - region: geographic region
    - product: product name
    - category: product category
    - quantity: order quantity
    - unit_cost: cost per unit
    - total_cost: quantity * unit_cost
    - defect_rate: percentage (0-5%)
    - delivery_days: days to deliver
    - on_time_delivery: 1 if on-time, 0 if late
    - shipping_mode: air, sea, truck, rail
    - shipping_cost: cost of shipping
    - warehouse_cost: storage cost
    """
    np.random.seed(42)
    n_rows = 500

    suppliers = [
        "Acme Corp",
        "BuildRight Inc",
        "Global Parts Ltd",
        "Superior Materials",
        "Reliable Suppliers Co",
    ]

    regions = ["North America", "Europe", "Asia Pacific", "Latin America", "Africa"]

    products = [
        "Steel Fasteners",
        "Aluminum Extrusions",
        "Plastic Components",
        "Rubber Seals",
        "Electronic Sensors",
        "Hydraulic Cylinders",
        "Control Systems",
        "Drive Belts",
    ]

    categories = [
        "Hardware",
        "Materials",
        "Electronics",
        "Mechanical",
        "Assembly",
    ]

    shipping_modes = ["air", "sea", "truck", "rail"]

    data = {
        "order_id": [f"ORD-{i:05d}" for i in range(1, n_rows + 1)],
        "order_date": [
            (datetime(2024, 1, 1) + timedelta(days=int(i * 365 / n_rows))).strftime(
                "%Y-%m-%d"
            )
            for i in range(n_rows)
        ],
        "supplier": np.random.choice(suppliers, n_rows),
        "region": np.random.choice(regions, n_rows),
        "product": np.random.choice(products, n_rows),
        "category": np.random.choice(categories, n_rows),
        "quantity": np.random.randint(10, 500, n_rows),
        "unit_cost": np.round(np.random.uniform(5, 100, n_rows), 2),
        "defect_rate": np.round(np.random.uniform(0, 5, n_rows), 2),
        "delivery_days": np.random.randint(5, 45, n_rows),
        "on_time_delivery": np.random.choice([0, 1], n_rows, p=[0.2, 0.8]),
        "shipping_mode": np.random.choice(shipping_modes, n_rows),
        "shipping_cost": np.round(np.random.uniform(100, 5000, n_rows), 2),
        "warehouse_cost": np.round(np.random.uniform(50, 2000, n_rows), 2),
    }

    df = pd.DataFrame(data)

    # Calculate total_cost
    df["total_cost"] = (df["quantity"] * df["unit_cost"]).round(2)

    return df


def get_table_schema() -> str:
    """
    Returns a formatted schema string describing the supply_chain table.
    Used by intent_parser to inject schema into GPT-5.1 prompt.

    Returns:
        str: Human-readable schema description
    """
    conn = get_connection()
    result = conn.execute("DESCRIBE supply_chain").fetchall()

    schema_lines = ["Table: supply_chain", ""]
    for col_name, col_type, *_ in result:
        schema_lines.append(f"  - {col_name} ({col_type})")

    return "\n".join(schema_lines)


def get_sample_rows(n: int = 5) -> pd.DataFrame:
    """
    Returns first N rows of supply_chain table as DataFrame.
    CRITICAL: Used by intent_parser to inject sample data into GPT-5.1 prompt.
    This helps the AI understand data distribution and available values.

    Args:
        n: Number of rows to return (default 5)

    Returns:
        pd.DataFrame: Sample rows from supply_chain table
    """
    conn = get_connection()
    df = conn.execute(f"SELECT * FROM supply_chain LIMIT {n}").df()
    return df


if __name__ == "__main__":
    # Quick test
    conn = get_connection()
    schema = get_table_schema()
    print(schema)
    print("\nSample rows:")
    print(get_sample_rows(3))
```

---

### 2.4 `engine/intent_parser.py` — Full Code

```python
import json
import os
from typing import Optional, Dict, Any
from openai import OpenAI
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# GPT-5.1 FUNCTION SCHEMA FOR DATA APP CREATION
# ============================================================================

APP_INTENT_FUNCTION = {
    "type": "function",
    "function": {
        "name": "create_data_app",
        "description": "Create an interactive data app definition with visualizations and filters",
        "parameters": {
            "type": "object",
            "properties": {
                "app_title": {
                    "type": "string",
                    "description": "Title of the data app (e.g., 'Supplier Performance Dashboard')",
                },
                "app_description": {
                    "type": "string",
                    "description": "Brief description of what the app does",
                },
                "components": {
                    "type": "array",
                    "description": "List of visualization components",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Unique component ID (e.g., 'chart_1')",
                            },
                            "type": {
                                "type": "string",
                                "enum": [
                                    "kpi_card",
                                    "bar_chart",
                                    "line_chart",
                                    "pie_chart",
                                    "scatter_plot",
                                    "table",
                                    "metric_highlight",
                                    "area_chart",
                                ],
                                "description": "Type of visualization",
                            },
                            "title": {
                                "type": "string",
                                "description": "Component title",
                            },
                            "sql_query": {
                                "type": "string",
                                "description": "SQL query to fetch data (SELECT from supply_chain table)",
                            },
                            "config": {
                                "type": "object",
                                "description": "Component-specific configuration",
                                "properties": {
                                    "x_axis": {
                                        "type": "string",
                                        "description": "Column name for X-axis (charts)",
                                    },
                                    "y_axis": {
                                        "type": "string",
                                        "description": "Column name for Y-axis (charts)",
                                    },
                                    "value_column": {
                                        "type": "string",
                                        "description": "Column to display as value (KPI cards, metrics)",
                                    },
                                    "metric_name": {
                                        "type": "string",
                                        "description": "Name of metric being displayed",
                                    },
                                    "format": {
                                        "type": "string",
                                        "enum": ["number", "currency", "percentage", "date"],
                                        "description": "Format for value display",
                                    },
                                    "columns": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Columns to display in table",
                                    },
                                    "sort_column": {
                                        "type": "string",
                                        "description": "Column to sort by",
                                    },
                                    "sort_order": {
                                        "type": "string",
                                        "enum": ["asc", "desc"],
                                        "description": "Sort order",
                                    },
                                },
                            },
                        },
                        "required": [
                            "id",
                            "type",
                            "title",
                            "sql_query",
                            "config",
                        ],
                    },
                },
                "filters": {
                    "type": "array",
                    "description": "List of filters users can apply",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Unique filter ID",
                            },
                            "name": {
                                "type": "string",
                                "description": "Filter display name",
                            },
                            "column": {
                                "type": "string",
                                "description": "Column to filter on",
                            },
                            "type": {
                                "type": "string",
                                "enum": [
                                    "multiselect",
                                    "date_range",
                                    "numeric_range",
                                ],
                                "description": "Type of filter",
                            },
                            "default_values": {
                                "type": "array",
                                "description": "Default selected values",
                            },
                        },
                        "required": [
                            "id",
                            "name",
                            "column",
                            "type",
                        ],
                    },
                },
            },
            "required": [
                "app_title",
                "app_description",
                "components",
                "filters",
            ],
        },
    },
}

# ============================================================================
# SYSTEM PROMPT (DYNAMIC — NOT HARDCODED SCHEMA)
# ============================================================================

SYSTEM_PROMPT_TEMPLATE = """You are an expert data engineer helping users create interactive data dashboards.

The user has a supply chain dataset with the following structure:

{schema}

Sample data (first 5 rows):
{sample_data}

Based on the user's request, create an app definition that:
1. Uses SQL queries to fetch the right data
2. Includes appropriate visualizations (charts, tables, KPIs)
3. Provides useful filters for exploration
4. Follows the app_definition schema exactly

IMPORTANT:
- All SQL queries must be valid DuckDB syntax
- All SQL queries must SELECT FROM the 'supply_chain' table
- Only use columns that exist in the schema above
- Keep queries efficient (avoid SELECT *)
- For aggregations, use GROUP BY appropriately
- For filters, the column name must match exactly what's in the schema

Return the app definition as a JSON object via the create_data_app function.
"""


def parse_intent(
    user_message: str,
    existing_app: Optional[Dict[str, Any]] = None,
    table_schema: Optional[str] = None,
    sample_data: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Parse user intent and return an app_definition JSON structure.

    This function:
    1. Injects dynamic schema and sample data into the system prompt
    2. Sends user message + schema to GPT-5.1 with function calling
    3. Forces tool_choice to create_data_app to ensure structured output
    4. Returns the parsed app_definition

    Supports two modes:
    - NEW BUILD: Create a new app from scratch (existing_app=None)
    - CONVERSATIONAL REFINEMENT: Modify existing app based on user feedback

    Args:
        user_message: User's natural language request
        existing_app: Current app definition (if refining). None for new apps.
        table_schema: Formatted schema string (from sample_data_loader.get_table_schema())
        sample_data: Sample rows as string (from sample_data_loader.get_sample_rows())

    Returns:
        Dict[str, Any]: app_definition JSON matching the schema

    Raises:
        ValueError: If GPT-5.1 response is invalid or missing function call
    """
    from data.sample_data_loader import get_table_schema, get_sample_rows

    # Load schema and sample data if not provided
    if table_schema is None:
        table_schema = get_table_schema()

    if sample_data is None:
        sample_df = get_sample_rows(5)
        sample_data = sample_df.to_string()

    # Inject schema into system prompt
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        schema=table_schema,
        sample_data=sample_data,
    )

    # For refinement mode, include existing app in context
    if existing_app:
        system_prompt += f"\n\nCurrent app definition:\n{json.dumps(existing_app, indent=2)}\n\nUser is asking to refine this app."

    # Initialize OpenAI client
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    # Call GPT-5.1 with function calling
    try:
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-5.1"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            functions=[APP_INTENT_FUNCTION],
            function_call={"name": "create_data_app"},  # Force this function
            temperature=0.3,
            max_tokens=4096,
        )
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        raise ValueError(f"Failed to parse intent: {e}")

    # Extract function call from response
    if response.choices[0].finish_reason != "function_call":
        raise ValueError(
            "GPT-5.1 did not return a function call. "
            "Ensure the prompt and schema are clear."
        )

    function_call = response.choices[0].message.function_call
    if function_call.name != "create_data_app":
        raise ValueError(f"Unexpected function call: {function_call.name}")

    # Parse the app_definition from function arguments
    try:
        app_definition = json.loads(function_call.arguments)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse function arguments: {e}")
        raise ValueError(f"Invalid JSON in function call: {e}")

    logger.info(f"✓ Parsed intent into app with {len(app_definition.get('components', []))} components")

    return app_definition


if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)

    test_message = "Show me supplier defect rates by region with on-time delivery percentage"
    result = parse_intent(test_message)
    print(json.dumps(result, indent=2))
```

---

### 2.5 `engine/executor.py` — Full Code

```python
import duckdb
from typing import Optional, List, Dict, Any
import pandas as pd
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# FILTER APPLICATION & SUBQUERY WRAPPING
# ============================================================================


def _build_filter_where_clause(filters: Optional[Dict[str, Any]]) -> str:
    """
    Build a WHERE clause from user-applied filters.

    Supports:
    - multiselect: column IN (val1, val2, ...)
    - date_range: column BETWEEN date1 AND date2
    - numeric_range: column BETWEEN num1 AND num2

    Args:
        filters: Dict mapping filter_id to selected values
                 Example: {"region_filter": ["North America", "Europe"]}

    Returns:
        str: WHERE clause (e.g., "WHERE region IN ('North America', 'Europe')")
             Returns empty string if no filters
    """
    if not filters:
        return ""

    where_conditions = []

    for filter_id, filter_value in filters.items():
        # For simplicity, assume filter_id maps to column name
        # In production, look up the column from app_definition.filters
        column_name = filter_id.replace("_filter", "")

        if isinstance(filter_value, list):
            # Multiselect: IN clause
            quoted_values = [f"'{v}'" for v in filter_value]
            where_conditions.append(f"{column_name} IN ({','.join(quoted_values)})")
        elif isinstance(filter_value, dict) and "start" in filter_value:
            # Date/numeric range: BETWEEN clause
            start = filter_value["start"]
            end = filter_value.get("end", start)
            where_conditions.append(f"{column_name} BETWEEN '{start}' AND '{end}'")

    if where_conditions:
        return "WHERE " + " AND ".join(where_conditions)
    return ""


def execute_query(
    conn: duckdb.DuckDBPyConnection,
    sql_query: str,
    filters: Optional[Dict[str, Any]] = None,
) -> pd.DataFrame:
    """
    Execute a SQL query with optional filter injection.

    For safety and flexibility, wraps the query as a subquery and applies
    filters via WHERE clause (if provided).

    Args:
        conn: DuckDB connection
        sql_query: SQL query to execute
        filters: Optional dict of filters to apply

    Returns:
        pd.DataFrame: Query results

    Raises:
        Exception: If query fails
    """
    where_clause = _build_filter_where_clause(filters)

    if where_clause:
        # Wrap original query as subquery and apply filters
        wrapped_query = f"SELECT * FROM ({sql_query}) AS filtered_data {where_clause}"
        logger.info(f"Applied filters. Wrapped query: {wrapped_query[:100]}...")
    else:
        wrapped_query = sql_query

    try:
        df = conn.execute(wrapped_query).df()
        logger.info(f"✓ Query executed: {len(df)} rows returned")
        return df
    except Exception as e:
        logger.error(f"Query execution failed: {e}\nQuery: {wrapped_query}")
        raise


def execute_app_components(
    conn: duckdb.DuckDBPyConnection,
    app_definition: Dict[str, Any],
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute all components in an app_definition and return aggregated results.

    This function:
    1. Iterates through each component in app_definition
    2. Executes the component's SQL query (with filters applied)
    3. Returns results keyed by component_id

    The returned dict is passed to validator.validate_and_explain() for
    validation and explanation generation.

    Args:
        conn: DuckDB connection
        app_definition: App definition dict with components list
        filters: Optional user-applied filters

    Returns:
        Dict[str, Any]:
            {
                "component_id_1": pd.DataFrame (results),
                "component_id_2": pd.DataFrame (results),
                ...
            }
    """
    execution_results = {}

    components = app_definition.get("components", [])
    logger.info(f"Executing {len(components)} components...")

    for component in components:
        component_id = component.get("id")
        sql_query = component.get("sql_query")

        try:
            df = execute_query(conn, sql_query, filters)
            execution_results[component_id] = {
                "status": "success",
                "data": df,
                "row_count": len(df),
            }
        except Exception as e:
            logger.error(f"Component {component_id} failed: {e}")
            execution_results[component_id] = {
                "status": "error",
                "error": str(e),
                "row_count": 0,
            }

    return execution_results


if __name__ == "__main__":
    # Quick test
    from data.sample_data_loader import get_connection

    logging.basicConfig(level=logging.INFO)

    conn = get_connection()

    # Test query
    test_query = "SELECT supplier, AVG(defect_rate) as avg_defect FROM supply_chain GROUP BY supplier"
    result = execute_query(conn, test_query)
    print(result)

    # Test with filters
    test_filters = {"region_filter": ["North America", "Europe"]}
    result_filtered = execute_query(conn, test_query, test_filters)
    print("\nFiltered result:")
    print(result_filtered)
```

---

### 2.6 `engine/validator.py` — Full Code

```python
from typing import Dict, Any, List
import pandas as pd
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# VALIDATION RULES & THRESHOLDS
# ============================================================================

VALIDATION_CONFIG = {
    "kpi_card": {
        "min_rows": 1,
        "max_rows": 1,
        "expected_columns": 1,
    },
    "metric_highlight": {
        "min_rows": 1,
        "max_rows": 1,
        "expected_columns": 1,
    },
    "table": {
        "min_rows": 1,
        "max_rows": 1000,
        "max_columns": 20,
    },
    "bar_chart": {
        "min_categories": 2,
        "max_categories": 50,
    },
    "line_chart": {
        "min_points": 3,
        "max_points": 500,
    },
    "pie_chart": {
        "min_slices": 2,
        "max_slices": 12,
    },
    "scatter_plot": {
        "min_points": 3,
        "max_points": 1000,
    },
    "area_chart": {
        "min_points": 3,
        "max_points": 500,
    },
}


def _validate_component(
    component_type: str,
    result: Dict[str, Any],
) -> tuple[bool, List[str]]:
    """
    Validate a single component's execution result.

    Args:
        component_type: Type of component (bar_chart, kpi_card, etc.)
        result: Execution result dict with 'status' and 'data'

    Returns:
        (is_valid, list_of_warnings)
    """
    warnings = []

    if result.get("status") == "error":
        warnings.append(f"Query failed: {result.get('error', 'Unknown error')}")
        return False, warnings

    df = result.get("data")
    if df is None or len(df) == 0:
        warnings.append("Query returned no data (empty result set)")
        return False, warnings

    config = VALIDATION_CONFIG.get(component_type, {})
    row_count = len(df)

    # Check row count constraints
    if "min_rows" in config and row_count < config["min_rows"]:
        warnings.append(
            f"Expected at least {config['min_rows']} row(s), got {row_count}"
        )

    if "max_rows" in config and row_count > config["max_rows"]:
        warnings.append(
            f"Expected at most {config['max_rows']} row(s), got {row_count}"
        )

    # Check column count
    if "max_columns" in config and len(df.columns) > config["max_columns"]:
        warnings.append(
            f"Too many columns ({len(df.columns)}). Max: {config['max_columns']}"
        )

    # For charts, check category/point counts
    if component_type in ["bar_chart", "pie_chart"]:
        if "min_categories" in config and len(df) < config["min_categories"]:
            warnings.append(
                f"Not enough categories ({len(df)}). Min: {config['min_categories']}"
            )
        if "max_categories" in config and len(df) > config["max_categories"]:
            warnings.append(
                f"Too many categories ({len(df)}). Max: {config['max_categories']}"
            )

    if component_type in ["line_chart", "area_chart", "scatter_plot"]:
        if "min_points" in config and len(df) < config["min_points"]:
            warnings.append(
                f"Not enough data points ({len(df)}). Min: {config['min_points']}"
            )
        if "max_points" in config and len(df) > config["max_points"]:
            warnings.append(
                f"Too many data points ({len(df)}). Max: {config['max_points']}"
            )

    is_valid = len(warnings) == 0
    return is_valid, warnings


def _generate_explanation(
    component_title: str,
    component_type: str,
    result: Dict[str, Any],
) -> str:
    """
    Generate a plain-English explanation of what the component shows.

    Args:
        component_title: Title of the component
        component_type: Type (bar_chart, table, etc.)
        result: Execution result dict

    Returns:
        str: Human-readable explanation
    """
    if result.get("status") == "error":
        return f"{component_title}: Failed to load data ({result.get('error')})"

    df = result.get("data")
    row_count = len(df)

    explanations = {
        "kpi_card": f"{component_title}: Displays a single metric value ({row_count} data point)",
        "metric_highlight": f"{component_title}: Highlights key metric ({row_count} data point)",
        "table": f"{component_title}: Shows {row_count} rows across {len(df.columns)} columns",
        "bar_chart": f"{component_title}: Compares {row_count} categories",
        "line_chart": f"{component_title}: Shows trend across {row_count} time points",
        "pie_chart": f"{component_title}: Breaks down into {row_count} segments",
        "scatter_plot": f"{component_title}: Plots {row_count} data points",
        "area_chart": f"{component_title}: Displays area trend with {row_count} points",
    }

    return explanations.get(
        component_type,
        f"{component_title}: {component_type} visualization ({row_count} rows)",
    )


def validate_and_explain(
    app_definition: Dict[str, Any],
    execution_results: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validate all components and generate explanations.

    This function:
    1. Checks each component result against validation rules
    2. Collects warnings and status for each component
    3. Generates plain-English explanations
    4. Returns overall validation status

    Args:
        app_definition: App definition with components list
        execution_results: Dict of execution results keyed by component_id

    Returns:
        Dict[str, Any]:
            {
                "overall_status": "success" | "warning" | "error",
                "components": [
                    {
                        "id": "component_id",
                        "status": "success" | "warning" | "error",
                        "warnings": [...],
                        "explanation": "...",
                    },
                    ...
                ],
                "total_warnings": int,
            }
    """
    components = app_definition.get("components", [])
    validation_report = []
    total_warnings = 0
    overall_status = "success"

    for component in components:
        component_id = component.get("id")
        component_type = component.get("type")
        component_title = component.get("title", component_id)

        result = execution_results.get(component_id, {})

        # Validate
        is_valid, warnings = _validate_component(component_type, result)

        # Generate explanation
        explanation = _generate_explanation(component_title, component_type, result)

        # Determine status
        status = "success" if is_valid else ("warning" if warnings else "error")

        validation_report.append(
            {
                "id": component_id,
                "title": component_title,
                "type": component_type,
                "status": status,
                "warnings": warnings,
                "explanation": explanation,
            }
        )

        if not is_valid:
            overall_status = "warning" if overall_status == "success" else "error"

        total_warnings += len(warnings)

    logger.info(
        f"✓ Validation complete: {overall_status} "
        f"({total_warnings} warnings across {len(components)} components)"
    )

    return {
        "overall_status": overall_status,
        "components": validation_report,
        "total_warnings": total_warnings,
    }


if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)

    sample_result = {
        "status": "success",
        "data": pd.DataFrame({"supplier": ["A", "B", "C"], "defect_rate": [2.1, 1.5, 3.2]}),
        "row_count": 3,
    }

    app = {
        "components": [
            {
                "id": "chart_1",
                "type": "bar_chart",
                "title": "Defect Rates",
            }
        ]
    }

    results = {"chart_1": sample_result}

    validation = validate_and_explain(app, results)
    print(validation)
```

---

### 2.7 `engine/governance.py` — Full Code (Skeleton + Integration)

```python
import re
from typing import Dict, Any, List
from config import PII_PATTERNS, ROLES
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# PII DETECTION
# ============================================================================


def _detect_pii(text: str) -> List[Dict[str, Any]]:
    """
    Scan text for personally identifiable information (PII).

    Args:
        text: Text to scan (typically from SQL query or data)

    Returns:
        List of detected PII items: [{"type": "ssn", "value": "xxx-xx-xxxx"}, ...]
    """
    detected = []

    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.finditer(pattern, str(text))
        for match in matches:
            detected.append(
                {
                    "type": pii_type,
                    "value": match.group(),
                }
            )

    return detected


# ============================================================================
# ACCESS CONTROL
# ============================================================================


def _check_access_control(role: str, capability: str) -> bool:
    """
    Check if a role has a specific capability.

    Args:
        role: Role name (admin, analyst, viewer)
        capability: Required capability

    Returns:
        bool: True if role has capability
    """
    role_config = ROLES.get(role, {})
    return capability in role_config.get("capabilities", [])


# ============================================================================
# QUERY COMPLEXITY CHECK
# ============================================================================


def _check_query_complexity(sql_query: str) -> Dict[str, Any]:
    """
    Analyze query complexity (joins, subqueries, aggregations).

    Args:
        sql_query: SQL query to analyze

    Returns:
        Dict with complexity metrics
    """
    query_upper = sql_query.upper()

    complexity = {
        "join_count": query_upper.count("JOIN"),
        "subquery_count": query_upper.count("SELECT") - 1,  # Exclude main SELECT
        "has_aggregation": any(agg in query_upper for agg in ["GROUP BY", "SUM(", "COUNT(", "AVG("]),
        "is_complex": False,
    }

    # Simple heuristic: complex if >2 joins or >1 subquery
    complexity["is_complex"] = complexity["join_count"] > 2 or complexity["subquery_count"] > 1

    return complexity


# ============================================================================
# DATA QUALITY CHECKS
# ============================================================================


def _check_data_quality(data_sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check data quality of execution results.

    Args:
        data_sample: Sample of execution results (rows, nulls, etc.)

    Returns:
        Dict with data quality metrics
    """
    return {
        "has_null_values": False,
        "has_duplicates": False,
        "overall_quality": "good",
    }


# ============================================================================
# EXPORT CONTROL
# ============================================================================


def _check_export_control(role: str, data_size: int) -> Dict[str, Any]:
    """
    Check if role can export data of this size.

    Args:
        role: User role
        data_size: Number of rows to export

    Returns:
        Dict with export permissions
    """
    from config import EXPORT_ROW_LIMIT

    role_config = ROLES.get(role, {})
    max_rows = role_config.get("max_rows_per_query", EXPORT_ROW_LIMIT)

    return {
        "can_export": data_size <= max_rows,
        "max_rows": max_rows,
        "requested_rows": data_size,
    }


# ============================================================================
# AUDIT TRAIL (PLACEHOLDER)
# ============================================================================


def _log_audit_trail(action: str, details: Dict[str, Any]) -> None:
    """
    Log governance actions to audit trail.

    In production, this would write to a persistent audit log.
    For hackathon, just log to stdout.

    Args:
        action: Action name (e.g., "execute_app", "export_data")
        details: Action details
    """
    logger.info(f"[AUDIT] {action}: {details}")


# ============================================================================
# MAIN GOVERNANCE FUNCTION
# ============================================================================


def run_governance_checks(
    app_definition: Dict[str, Any],
    role: str = "analyst",
    execution_results: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Run comprehensive governance checks on an app and its execution.

    This function:
    1. Scans for PII in SQL queries and results
    2. Checks access control based on role
    3. Analyzes query complexity
    4. Checks data quality
    5. Checks export permissions
    6. Logs audit trail

    Args:
        app_definition: App definition dict
        role: User role (admin, analyst, viewer)
        execution_results: Dict of execution results (optional)

    Returns:
        Dict[str, Any]:
            {
                "passed": bool,
                "role": str,
                "pii_detected": List,
                "access_granted": bool,
                "query_complexity": Dict,
                "data_quality": Dict,
                "export_allowed": bool,
                "warnings": List[str],
            }
    """
    passed = True
    warnings = []

    # 1. PII Detection
    pii_detected = []
    for component in app_definition.get("components", []):
        sql_query = component.get("sql_query", "")
        pii = _detect_pii(sql_query)
        if pii:
            pii_detected.extend(pii)
            warnings.append(f"⚠️ PII detected in component {component.get('id')}")

    if pii_detected:
        passed = False

    # 2. Access Control
    access_granted = _check_access_control(role, "create_app")
    if not access_granted:
        warnings.append(f"❌ Role '{role}' not allowed to create apps")
        passed = False

    # 3. Query Complexity
    query_complexity = {}
    for component in app_definition.get("components", []):
        sql_query = component.get("sql_query", "")
        complexity = _check_query_complexity(sql_query)
        query_complexity[component.get("id")] = complexity
        if complexity["is_complex"]:
            warnings.append(
                f"⚠️ Component {component.get('id')} has complex query"
            )

    # 4. Data Quality (if results provided)
    data_quality = {}
    if execution_results:
        data_quality = _check_data_quality(execution_results)

    # 5. Export Control
    total_rows = 0
    if execution_results:
        for result in execution_results.values():
            total_rows += result.get("row_count", 0)

    export_check = _check_export_control(role, total_rows)
    export_allowed = export_check["can_export"]

    if not export_allowed:
        warnings.append(
            f"⚠️ Role '{role}' cannot export {total_rows} rows "
            f"(limit: {export_check['max_rows']})"
        )

    # 6. Audit Trail
    _log_audit_trail(
        "governance_check",
        {
            "role": role,
            "app_id": app_definition.get("app_title"),
            "passed": passed,
            "warnings_count": len(warnings),
        },
    )

    return {
        "passed": passed,
        "role": role,
        "pii_detected": pii_detected,
        "access_granted": access_granted,
        "query_complexity": query_complexity,
        "data_quality": data_quality,
        "export_allowed": export_allowed,
        "warnings": warnings,
    }


if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)

    sample_app = {
        "app_title": "Test App",
        "components": [
            {
                "id": "chart_1",
                "sql_query": "SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier",
            }
        ],
    }

    result = run_governance_checks(sample_app, role="analyst")
    print(result)
```

---

### 2.8 `engine/pipeline.py` — Full Pipeline Runner (for Streamlit integration)

**IMPORTANT:** We are using **Streamlit**, NOT FastAPI. There is no REST API. Person 2's `app.py` (Streamlit) will import your engine functions directly as Python calls. This file provides a convenience wrapper that runs the full pipeline in one call.

```python
import logging
from typing import Optional, Dict, Any

from data.sample_data_loader import get_connection, get_table_schema, get_sample_data
from engine.intent_parser import parse_intent
from engine.executor import execute_app_components
from engine.validator import validate_and_explain
from engine.governance import run_governance_checks

logger = logging.getLogger(__name__)


def run_pipeline(
    user_message: str,
    existing_app: Optional[Dict[str, Any]] = None,
    filters: Optional[Dict[str, Any]] = None,
    role: str = "analyst",
) -> Dict[str, Any]:
    """
    Full StackForge pipeline: parse → execute → validate → govern.

    This is the main entry point that Person 2's Streamlit app calls.

    Args:
        user_message: Natural language query from the user
        existing_app: Previous app_definition for conversational refinement
        filters: User-selected filter values from the sidebar
        role: User role (admin/analyst/viewer)

    Returns:
        Dict with keys: app_definition, execution_results, validation, governance
    """
    conn = get_connection()

    # 1. Parse intent → app_definition
    app_definition = parse_intent(
        user_message,
        existing_app=existing_app,
        table_schema=get_table_schema(conn),
        sample_data=get_sample_data(conn),
    )

    # 2. Execute SQL queries via DuckDB
    execution_results = execute_app_components(
        conn, app_definition, filters=filters
    )

    # 3. Validate and generate explanations
    validation = validate_and_explain(app_definition, execution_results)

    # 4. Run governance checks
    governance = run_governance_checks(
        app_definition, role=role, execution_results=execution_results
    )

    # Convert DataFrames to dicts for Streamlit/Plotly consumption
    for component_id, result in execution_results.items():
        if "data" in result and hasattr(result["data"], "to_dict"):
            result["data"] = result["data"].to_dict(orient="records")

    return {
        "app_definition": app_definition,
        "execution_results": execution_results,
        "validation": validation,
        "governance": governance,
    }
```

**How Person 2 calls this from Streamlit:**
```python
# In app.py (Person 2's file)
from engine.pipeline import run_pipeline

result = run_pipeline(
    user_message=user_input,
    existing_app=st.session_state.get("current_app"),
    filters=st.session_state.get("active_filters"),
    role=st.session_state.get("user_role", "analyst"),
)
st.session_state["current_app"] = result["app_definition"]
```

---

## SECTION 3: INTEGRATION CONTRACT — `app_definition` JSON Schema

This is the **critical interface** between Person 1's engine and Person 2's UI.

### 3.1 TypeScript-Style Type Definition

```typescript
interface AppDefinition {
  app_title: string;
  app_description: string;
  components: Component[];
  filters: Filter[];
  metadata?: {
    created_at: string;
    created_by: string;
    version: string;
  };
}

interface Component {
  id: string;
  type: ComponentType;
  title: string;
  sql_query: string;
  config: ComponentConfig;
}

type ComponentType =
  | "kpi_card"
  | "bar_chart"
  | "line_chart"
  | "pie_chart"
  | "scatter_plot"
  | "table"
  | "metric_highlight"
  | "area_chart";

interface ComponentConfig {
  // Common
  x_axis?: string;
  y_axis?: string;
  value_column?: string;
  metric_name?: string;
  format?: "number" | "currency" | "percentage" | "date";

  // Table-specific
  columns?: string[];
  sort_column?: string;
  sort_order?: "asc" | "desc";
}

interface Filter {
  id: string;
  name: string;
  column: string;
  type: FilterType;
  default_values?: (string | number | null)[];
}

type FilterType = "multiselect" | "date_range" | "numeric_range";
```

### 3.2 Example Output: "Show me supplier defect rates by region with on-time delivery percentage"

```json
{
  "app_title": "Supplier Defect Rates by Region",
  "app_description": "Analyze supplier defect rates and on-time delivery performance across regions",
  "components": [
    {
      "id": "chart_1",
      "type": "bar_chart",
      "title": "Average Defect Rate by Supplier & Region",
      "sql_query": "SELECT supplier, region, AVG(defect_rate) as avg_defect_rate FROM supply_chain GROUP BY supplier, region ORDER BY avg_defect_rate DESC",
      "config": {
        "x_axis": "supplier",
        "y_axis": "avg_defect_rate",
        "metric_name": "Defect Rate (%)",
        "format": "percentage"
      }
    },
    {
      "id": "chart_2",
      "type": "bar_chart",
      "title": "On-Time Delivery % by Region",
      "sql_query": "SELECT region, SUM(CASE WHEN on_time_delivery=1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as on_time_pct FROM supply_chain GROUP BY region ORDER BY on_time_pct DESC",
      "config": {
        "x_axis": "region",
        "y_axis": "on_time_pct",
        "metric_name": "On-Time Delivery %",
        "format": "percentage"
      }
    },
    {
      "id": "kpi_1",
      "type": "kpi_card",
      "title": "Average Defect Rate (All)",
      "sql_query": "SELECT AVG(defect_rate) as overall_defect_rate FROM supply_chain",
      "config": {
        "value_column": "overall_defect_rate",
        "metric_name": "Overall Defect Rate",
        "format": "percentage"
      }
    },
    {
      "id": "table_1",
      "type": "table",
      "title": "Supplier Details",
      "sql_query": "SELECT supplier, region, COUNT(*) as order_count, AVG(defect_rate) as avg_defect, SUM(CASE WHEN on_time_delivery=1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as on_time_pct FROM supply_chain GROUP BY supplier, region",
      "config": {
        "columns": ["supplier", "region", "order_count", "avg_defect", "on_time_pct"],
        "sort_column": "avg_defect",
        "sort_order": "desc"
      }
    }
  ],
  "filters": [
    {
      "id": "region_filter",
      "name": "Region",
      "column": "region",
      "type": "multiselect",
      "default_values": ["North America", "Europe"]
    },
    {
      "id": "supplier_filter",
      "name": "Supplier",
      "column": "supplier",
      "type": "multiselect",
      "default_values": null
    }
  ]
}
```

### 3.3 Component Types & Required Config Fields

| Component Type | Required Config Fields | Optional Fields | Purpose |
|---|---|---|---|
| `kpi_card` | `value_column`, `metric_name` | `format` | Single key metric display |
| `metric_highlight` | `value_column`, `metric_name` | `format` | Highlighted metric value |
| `bar_chart` | `x_axis`, `y_axis` | `metric_name`, `format` | Categorical comparison |
| `line_chart` | `x_axis`, `y_axis` | `metric_name` | Trend over time |
| `pie_chart` | `x_axis`, `y_axis` | `metric_name` | Part-to-whole comparison |
| `scatter_plot` | `x_axis`, `y_axis` | `metric_name` | Correlation analysis |
| `area_chart` | `x_axis`, `y_axis` | `metric_name` | Stacked/area trends |
| `table` | `columns` | `sort_column`, `sort_order` | Detailed data grid |

---

## SECTION 4: TIMELINE FOR PERSON 1

### Hour 0-1: Project Setup
- [ ] Clone repo, create .env, requirements.txt
- [ ] Create directory structure
- [ ] Run `pip install -r requirements.txt`
- [ ] Test DuckDB connection: `python data/sample_data_loader.py`
- [ ] Verify 500 rows of synthetic data loaded

### Hour 1-3: Intent Parser
- [ ] Implement `APP_INTENT_FUNCTION` schema (all component types)
- [ ] Implement `SYSTEM_PROMPT_TEMPLATE` (dynamic schema injection)
- [ ] Implement `parse_intent()` function with GPT-5.1 function calling
- [ ] Test with 3 prompts: supplier performance, regional analysis, product profitability
- [ ] Verify output matches `app_definition` contract exactly
- [ ] Test conversational refinement (existing_app parameter)

### Hour 3-5: Executor + Validator + Governance
- [ ] Implement `execute_query()` with filter injection
- [ ] Implement `execute_app_components()` batch execution
- [ ] Implement `validate_and_explain()` with warnings and explanations
- [ ] Create `governance.py` skeleton (complete code provided)
- [ ] Test governance checks on sample app

### Hour 5-6: Integration Testing
- [ ] Test full pipeline: parse → execute → validate → governance
- [ ] Verify SQL queries execute without errors
- [ ] Test filter injection (multiselect, date_range)
- [ ] Verify JSON serialization (DataFrames → dicts)
- [ ] Create mock test cases in `tests/` folder

### Hour 6-8: Edge Cases & Refinement
- [ ] Test conversational refinement (modifying existing apps)
- [ ] Test multi-component execution
- [ ] Handle empty result sets gracefully
- [ ] Test error handling and error messages
- [ ] Optimize prompt for accuracy

### Hour 8-10: Help Integration & Demo Prep
- [ ] Work with Person 2 on API integration
- [ ] Debug any schema mismatches
- [ ] Help Person 3 understand governance checks
- [ ] Prepare demo scenarios
- [ ] Documentation and docstrings

### Hour 10-14: Support & Optimization
- [ ] Support Person 2/3 with bug fixes
- [ ] Optimize SQL query generation
- [ ] Refine prompt based on demo feedback
- [ ] Handle edge cases discovered during testing

### Hour 14-19: Final Demo & Wrap-up
- [ ] Final testing and bug fixes
- [ ] Demo preparation
- [ ] Code cleanup and documentation
- [ ] Help team with final presentation

---

## SECTION 5: TESTING CHECKLIST

### Unit Tests: Intent Parser

- [ ] Test 1: Parse "Show me supplier defect rates by region" → Valid app_definition
  - Expected: 2-3 components, bar chart + KPI card
  - Verify: SQL queries are valid, filters include region

- [ ] Test 2: Parse "Add on-time delivery percentage" with existing_app → Refines app
  - Expected: New component added, not entire rebuild
  - Verify: Existing components unchanged, new component valid

- [ ] Test 3: Dynamic schema injection
  - Expected: Schema and sample rows included in prompt to GPT-5.1
  - Verify: Column names match supply_chain table exactly

- [ ] Test 4: All 6 templates parse correctly
  - Expected: Each template generates valid app with 3+ components
  - Verify: No SQL syntax errors, all queries use supply_chain table

### Unit Tests: Executor

- [ ] Test 5: Execute simple query
  - Input: `SELECT * FROM supply_chain LIMIT 10`
  - Expected: 10 rows returned

- [ ] Test 6: Execute aggregation query
  - Input: `SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier`
  - Expected: 5 supplier rows with averages

- [ ] Test 7: Filter injection - multiselect
  - Input: Query + `{"region_filter": ["North America", "Europe"]}`
  - Expected: Only rows matching regions returned

- [ ] Test 8: Filter injection - date range
  - Input: Query + `{"date_filter": {"start": "2024-01-01", "end": "2024-06-30"}}`
  - Expected: Only rows in date range returned

- [ ] Test 9: Execute app with all components
  - Input: Full app_definition with 4 components
  - Expected: All 4 queries executed, results keyed by component_id

### Unit Tests: Validator

- [ ] Test 10: Validate successful execution
  - Input: Component with 5 rows, type=bar_chart
  - Expected: Status=success, no warnings

- [ ] Test 11: Detect empty result set
  - Input: Component with 0 rows, type=bar_chart
  - Expected: Warning "Query returned no data"

- [ ] Test 12: Detect too many categories
  - Input: Bar chart with 60 categories
  - Expected: Warning "Too many categories (60). Max: 50"

- [ ] Test 13: Generate explanations
  - Input: Various component types with results
  - Expected: Human-readable explanation for each (e.g., "Compares 8 categories")

- [ ] Test 14: Overall validation status
  - Input: App with 1 success, 1 warning, 1 error
  - Expected: overall_status=warning, total_warnings=2

### Unit Tests: Governance

- [ ] Test 15: PII detection
  - Input: SQL query with SSN pattern
  - Expected: PII detected, warning generated

- [ ] Test 16: Role-based access control
  - Input: Role=viewer, capability=create_app
  - Expected: access_granted=False

- [ ] Test 17: Query complexity check
  - Input: Query with 3 joins + 2 subqueries
  - Expected: is_complex=True, warning generated

- [ ] Test 18: Export control
  - Input: Role=viewer, 15000 rows
  - Expected: export_allowed=False (viewer limit: 10k)

- [ ] Test 19: Audit trail logging
  - Input: Execute app as analyst
  - Expected: Audit log entry created with action details

### Integration Tests

- [ ] Test 20: Full pipeline - Parse → Execute → Validate → Governance
  - Input: User message "Show me cost breakdown by region"
  - Expected: Valid app_definition → execution_results → validation report → governance checks
  - Verify: All layers produce valid output

- [ ] Test 21: Conversational refinement
  - Step 1: Parse "Show supplier defect rates"
  - Step 2: Parse "Also add on-time delivery trend" with existing app
  - Expected: Step 2 refines Step 1, doesn't rebuild from scratch
  - Verify: Original components still present

- [ ] Test 22: API endpoints
  - POST /parse_intent with valid message
  - Expected: 200 status, valid app_definition
  - POST /execute_app with valid app_definition
  - Expected: 200 status, execution_results + validation + governance

- [ ] Test 23: Error handling
  - Send invalid SQL in execute_app
  - Expected: HTTP 400, error message in response
  - Verify: App doesn't crash, error logged

- [ ] Test 24: Dataset coverage
  - Execute queries for all 6 templates
  - Expected: Each template generates valid queries that execute
  - Verify: SQL uses all major columns (supplier, region, product, cost, defect, delivery, shipping)

---

## FINAL NOTES FOR PERSON 1

### Success Criteria

By the end of 19 hours, you must deliver:

1. ✅ **Complete Engine Layer** — All 5 core files (intent_parser, executor, validator, governance, config, data_loader) with working code
2. ✅ **Valid app_definition JSON** — Matches the contract schema exactly; Person 2 can parse and render it
3. ✅ **SQL Execution** — Queries run without errors in DuckDB; filters inject correctly
4. ✅ **Dynamic Schema** — Schema and sample rows injected at runtime, not hardcoded
5. ✅ **Conversational Refinement** — Existing apps can be modified, not rebuilt
6. ✅ **Validation & Explanations** — Clear warnings and user-friendly descriptions
7. ✅ **Governance Integration** — Person 3 can plug into run_governance_checks() and extend
8. ✅ **Pipeline Runner** — `engine/pipeline.py` run_pipeline() works end-to-end and Person 2 can call it directly from Streamlit
9. ✅ **Testing Coverage** — 24 test cases covering intent parser, executor, validator, governance, integration

### Communication with Team

- **Person 2 (UI):** Agree on app_definition schema (SECTION 3). They consume your JSON and render it.
- **Person 3 (Governance):** They extend `governance.py` at Hour 2 onwards. You provide the skeleton; they add checks.
- **Full Team:** Daily sync at Hours 6 and 12 to align on integration points.

### Debugging Tips

- If GPT-5.1 generates invalid SQL: check schema injection (is it showing all columns?)
- If filters don't apply: verify filter_id maps to column name correctly
- If validation fails: check component type and row count (KPI cards expect exactly 1 row)
- If Person 2 can't parse JSON: verify no DataFrames in output (convert to dicts)

### Resources

- DuckDB Docs: https://duckdb.org/docs/
- OpenAI Function Calling: https://platform.openai.com/docs/guides/function-calling
- Streamlit Docs: https://docs.streamlit.io/ (Person 2's domain, but good to understand how your engine gets called)

**Good luck! You've got this. 🚀**
