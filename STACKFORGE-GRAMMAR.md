# StackForge Compiler Grammar

## What This Document Is

StackForge is not a chatbot that makes charts. It's a **five-stage compiler** that takes natural language as input and produces a structured, executable, governed data application as output. This document defines the formal grammar of that compilation process — the rules, types, constraints, and transformations that make it work.

---

## Stage 1: Lexical Analysis — Schema Injection

Before any user input is processed, the compiler builds its **symbol table** by introspecting the live database at runtime.

**Inputs:**
- `DESCRIBE supply_chain` → column names and types
- `SELECT * FROM supply_chain LIMIT 5` → sample values

**Output:** A dynamically constructed system prompt injected into the LLM context:

```
Table: supply_chain

  - order_id (VARCHAR)
  - order_date (VARCHAR)
  - supplier (VARCHAR)
  - region (VARCHAR)
  - product (VARCHAR)
  - category (VARCHAR)
  - quantity (BIGINT)
  - unit_cost (DOUBLE)
  - total_cost (DOUBLE)
  - defect_rate (DOUBLE)
  - delivery_days (BIGINT)
  - on_time_delivery (BIGINT)
  - shipping_mode (VARCHAR)
  - shipping_cost (DOUBLE)
  - warehouse_cost (DOUBLE)
```

Plus 5 sample rows so the LLM understands data distribution, value ranges, and categorical options (e.g., it learns that `region` contains "North America", "Europe", "Asia Pacific", etc. — it doesn't guess).

**Why this matters:** The schema is never hardcoded. If you swap the CSV or add columns, the compiler adapts automatically. This is what makes StackForge a *factory* and not a one-off demo.

---

## Stage 2: Parsing — Natural Language → `app_definition` AST

The user's natural language request is the **source code**. GPT-5.1 with forced function calling is the **parser**. The output is a structured JSON object called `app_definition` — this is StackForge's equivalent of an Abstract Syntax Tree (AST).

### The Function Schema (i.e., the Grammar Rules)

The parser is constrained by a formal schema passed to GPT-5.1 via the `create_data_app` function definition. GPT-5.1 cannot return free-form text — it *must* emit a valid `app_definition` or the call fails. This is the key architectural decision: `tool_choice: {"name": "create_data_app"}` forces structured output.

### The `app_definition` Grammar

```
AppDefinition ::= {
    app_title       : STRING,          -- Human-readable title
    app_description : STRING,          -- What the app does
    components      : Component[],     -- 1 to 8 visualization nodes
    filters         : Filter[]         -- 0 or more interactive filters
}
```

### Component Production Rules

```
Component ::= {
    id        : STRING,                -- Unique identifier (e.g., "chart_1")
    type      : ComponentType,         -- Terminal symbol from enum
    title     : STRING,                -- Display title
    sql_query : SQL_QUERY,             -- Executable DuckDB SQL
    config    : ComponentConfig        -- Type-specific rendering hints
}

ComponentType ::=
    "kpi_card"          -- Single scalar value (expects exactly 1 row)
  | "metric_highlight"  -- Emphasized scalar (expects exactly 1 row)
  | "bar_chart"         -- Categorical comparison (2-50 categories)
  | "line_chart"        -- Trend over time (3-500 points)
  | "pie_chart"         -- Part-to-whole (2-12 slices)
  | "scatter_plot"      -- Correlation (3-1000 points)
  | "area_chart"        -- Stacked/area trend (3-500 points)
  | "table"             -- Data grid (1-1000 rows, max 20 columns)
```

### ComponentConfig Production Rules (Type-Dependent)

```
ComponentConfig ::= {
    -- For charts (bar, line, pie, scatter, area):
    x_axis?      : COLUMN_NAME,       -- Column mapped to X axis
    y_axis?      : COLUMN_NAME,       -- Column mapped to Y axis

    -- For scalars (kpi_card, metric_highlight):
    value_column? : COLUMN_NAME,      -- Column containing the value
    metric_name?  : STRING,           -- Label for the metric

    -- For tables:
    columns?     : COLUMN_NAME[],     -- Columns to display
    sort_column? : COLUMN_NAME,       -- Column to sort by
    sort_order?  : "asc" | "desc",    -- Sort direction

    -- Universal:
    format?      : "number" | "currency" | "percentage" | "date"
}
```

### Required Config by Component Type

| Type               | Required Fields              | Optional Fields           |
|--------------------|------------------------------|---------------------------|
| `kpi_card`         | `value_column`, `metric_name`| `format`                  |
| `metric_highlight` | `value_column`, `metric_name`| `format`                  |
| `bar_chart`        | `x_axis`, `y_axis`           | `metric_name`, `format`   |
| `line_chart`       | `x_axis`, `y_axis`           | `metric_name`             |
| `pie_chart`        | `x_axis`, `y_axis`           | `metric_name`             |
| `scatter_plot`     | `x_axis`, `y_axis`           | `metric_name`             |
| `area_chart`       | `x_axis`, `y_axis`           | `metric_name`             |
| `table`            | `columns`                    | `sort_column`, `sort_order`|

### Filter Production Rules

```
Filter ::= {
    id             : STRING,           -- Unique identifier (e.g., "region_filter")
    name           : STRING,           -- Display label (e.g., "Region")
    column         : COLUMN_NAME,      -- Column to filter on
    type           : FilterType,       -- How the filter behaves
    default_values?: ANY[]             -- Pre-selected values (optional)
}

FilterType ::=
    "multiselect"    -- IN (val1, val2, ...) → dropdown with checkboxes
  | "date_range"     -- BETWEEN date1 AND date2 → date picker
  | "numeric_range"  -- BETWEEN num1 AND num2 → slider
```

### SQL_QUERY Terminal Rules

Every `sql_query` in a component must satisfy:

1. Must be valid **DuckDB SQL syntax**
2. Must `SELECT FROM supply_chain` (the only table)
3. Must only reference columns that exist in the live schema
4. Must avoid `SELECT *` (explicit columns only)
5. Must use `GROUP BY` when aggregating
6. For KPI/metric types: must return exactly 1 row
7. For charts: should return 2-50 rows (bar/pie) or 3-500 rows (line/area/scatter)

---

## Stage 3: Code Execution — SQL Against DuckDB

Each component's `sql_query` is executed against the embedded DuckDB database. Filters are applied via **subquery wrapping**, not query mutation:

```
Original:  SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier
Filtered:  SELECT * FROM (
             SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier
           ) AS filtered_data
           WHERE region IN ('North America', 'Europe')
```

### Filter Application Grammar

```
FilterClause ::= ""                                              -- No filters
               | "WHERE " + Condition (" AND " + Condition)*     -- One or more

Condition ::=
    COLUMN_NAME " IN (" + QuotedValues + ")"                     -- multiselect
  | COLUMN_NAME " BETWEEN '" + START + "' AND '" + END + "'"    -- date_range
  | COLUMN_NAME " BETWEEN '" + START + "' AND '" + END + "'"    -- numeric_range

QuotedValues ::= "'" + VALUE + "'" ("," + "'" + VALUE + "'")*
```

### Execution Output Shape

```
ExecutionResults ::= {
    [component_id] : ComponentResult
}

ComponentResult ::=
    { status: "success", data: DataFrame → dict[], row_count: INT }
  | { status: "error",  error: STRING,            row_count: 0   }
```

---

## Stage 4: Validation — Type Checking the Output

Every component result is validated against type-specific constraints. This is StackForge's equivalent of a **type checker** — ensuring the AST produced valid executable output.

### Validation Constraint Table

| ComponentType      | Constraint          | Rule                    |
|--------------------|---------------------|-------------------------|
| `kpi_card`         | `expected_rows`     | Exactly 1               |
| `metric_highlight` | `expected_rows`     | Exactly 1               |
| `bar_chart`        | `min_categories`    | >= 2                    |
| `bar_chart`        | `max_categories`    | <= 50                   |
| `line_chart`       | `min_points`        | >= 3                    |
| `line_chart`       | `max_points`        | <= 500                  |
| `pie_chart`        | `min_slices`        | >= 2                    |
| `pie_chart`        | `max_slices`        | <= 12                   |
| `scatter_plot`     | `min_points`        | >= 3                    |
| `scatter_plot`     | `max_points`        | <= 1000                 |
| `area_chart`       | `min_points`        | >= 3                    |
| `area_chart`       | `max_points`        | <= 500                  |
| `table`            | `min_rows`          | >= 1                    |
| `table`            | `max_rows`          | <= 1000                 |
| `table`            | `max_columns`       | <= 20                   |

### Validation Output Grammar

```
ValidationReport ::= {
    overall_status : "success" | "warning" | "error",
    total_warnings : INT,
    components     : ComponentValidation[]
}

ComponentValidation ::= {
    id          : STRING,
    title       : STRING,
    type        : ComponentType,
    status      : "success" | "warning" | "error",
    warnings    : STRING[],
    explanation : STRING        -- Plain-English description of what the component shows
}
```

### Explanation Templates

```
kpi_card         → "{title}: Displays a single metric value ({n} data point)"
metric_highlight → "{title}: Highlights key metric ({n} data point)"
table            → "{title}: Shows {rows} rows across {cols} columns"
bar_chart        → "{title}: Compares {n} categories"
line_chart       → "{title}: Shows trend across {n} time points"
pie_chart        → "{title}: Breaks down into {n} segments"
scatter_plot     → "{title}: Plots {n} data points"
area_chart       → "{title}: Displays area trend with {n} points"
```

---

## Stage 5: Governance — Security & Compliance Pass

The final compiler stage applies security, access control, and audit rules before the app reaches the user. This is StackForge's equivalent of a **linker/loader** that enforces runtime constraints.

### Governance Checks (in order)

```
GovernancePass ::=
    PIIDetection
  → AccessControl
  → QueryComplexity
  → DataQuality
  → ExportControl
  → AuditTrail
```

### 5a. PII Detection

Scans all `sql_query` strings for regex patterns:

| PII Type     | Pattern                                          |
|-------------|--------------------------------------------------|
| SSN          | `\b\d{3}-\d{2}-\d{4}\b`                         |
| Credit Card  | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`   |
| Email        | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z\|a-z]{2,}\b` |
| Phone        | `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`                 |
| Passport     | `\b[A-Z]{2}\d{6,8}\b`                           |
| IP Address   | `\b(?:\d{1,3}\.){3}\d{1,3}\b`                   |

If any PII is found → `passed = false`, warning generated.

### 5b. Role-Based Access Control (RBAC)

```
Role ::= "admin" | "analyst" | "viewer"

RoleCapabilities ::= {
    admin   : [view_all_data, export_data, create_app, modify_app, delete_app, view_pii, audit_trail]
    analyst : [view_all_data, export_data, create_app, modify_app]
    viewer  : [view_all_data]
}

RoleRowLimits ::= {
    admin   : unlimited
    analyst : 100,000
    viewer  : 10,000
}
```

If role lacks `create_app` capability → `access_granted = false`.

### 5c. Query Complexity

```
ComplexityCheck ::= {
    join_count     : COUNT("JOIN" in sql_query),
    subquery_count : COUNT("SELECT" in sql_query) - 1,
    has_aggregation: ANY(["GROUP BY", "SUM(", "COUNT(", "AVG("] in sql_query),
    is_complex     : join_count > 2 OR subquery_count > 1
}
```

### 5d. Export Control

```
ExportAllowed ::= total_result_rows <= RoleRowLimits[role]
```

### Governance Output Grammar

```
GovernanceReport ::= {
    passed           : BOOLEAN,        -- All checks passed?
    role             : Role,
    pii_detected     : PIIMatch[],
    access_granted   : BOOLEAN,
    query_complexity : { [component_id]: ComplexityCheck },
    data_quality     : DataQualityReport,
    export_allowed   : BOOLEAN,
    warnings         : STRING[]
}
```

---

## The Full Compilation Pipeline

```
User Request (natural language)
       │
       ▼
┌─────────────────────────┐
│ Stage 1: Schema Inject  │  DESCRIBE + LIMIT 5 → system prompt
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Stage 2: Parse Intent   │  GPT-5.1 + forced function calling → app_definition AST
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Stage 3: Execute SQL    │  Each component.sql_query → DuckDB → DataFrame
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Stage 4: Validate       │  Type-check results against component constraints
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Stage 5: Govern         │  PII scan → RBAC → complexity → export control → audit
└────────────┬────────────┘
             │
             ▼
      Final Output:
      {
        app_definition,       ← The AST
        execution_results,    ← The compiled output
        validation,           ← The type-check report
        governance            ← The security clearance
      }
```

---

## Conversational Refinement (AST Mutation)

StackForge supports **incremental compilation**. When `existing_app` is passed to `parse_intent()`, the system prompt includes the current AST and instructs GPT-5.1 to *modify* it rather than rebuild from scratch.

```
Mode 1 — New Build:     parse_intent("Show defect rates")           → fresh AST
Mode 2 — Refinement:    parse_intent("Add delivery trend", existing_app=AST) → mutated AST
```

This means the user can iteratively build complex dashboards through conversation, and each refinement preserves the components they've already approved.

---

## Concrete Example

**Input:** `"Show me supplier defect rates by region with on-time delivery percentage"`

**Output AST:**

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

This AST then flows through execution (4 SQL queries), validation (row counts checked against component type rules), and governance (PII scan, RBAC check, complexity analysis) — producing the four-key result object that Person 2's Streamlit app renders into a live interactive dashboard.
