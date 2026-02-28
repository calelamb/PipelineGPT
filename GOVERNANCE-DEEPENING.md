# GOVERNANCE DEEPENING PRD

## Context

You are Person 1 (The Engine) on the `engine` branch of StackForge. The governance skeleton in `engine/governance.py` passes all 55 tests but is thin — hardcoded data quality checks, stdout-only audit logging, no SQL sanitization, and RBAC that only checks `create_app`. This PRD deepens governance into a **judge-impressive, demo-ready security layer**.

**Files you will modify (all on your `engine` branch):**
- `engine/governance.py` — The main file. Deepen every function.
- `config.py` — Add new governance constants (SQL blocklist, sensitivity levels, column classifications).
- `engine/pipeline.py` — Add pre-execution governance gate (block before SQL runs, not just report after).
- `tests/test_governance.py` — Add tests for every new feature.

**Files you must NOT touch:**
- `ui/` anything — Person 2 owns this
- `engine/intent_parser.py` — Already complete and passing
- `engine/executor.py` — Already complete and passing

---

## SECTION 1: ENHANCED RBAC — THE PERMISSION MATRIX

The current ROLES config only has capabilities as a flat list. Deepen it into a **full permission matrix** that controls what each role can see, do, and export.

### 1.1 Update `config.py` — New ROLES Structure

Replace the existing ROLES dict with:

```python
# ============================================================================
# ROLE-BASED ACCESS CONTROL (ENHANCED)
# ============================================================================

ROLES = {
    "admin": {
        "display_name": "Administrator",
        "capabilities": [
            "view_all_data",
            "view_sensitive_data",
            "view_pii",
            "export_data",
            "export_sensitive",
            "create_app",
            "modify_app",
            "delete_app",
            "view_audit_trail",
            "manage_roles",
            "bypass_row_limit",
        ],
        "max_rows_per_query": None,         # No limit
        "max_components_per_app": 8,
        "allowed_component_types": None,    # All types
        "can_use_templates": True,
        "session_timeout_minutes": 480,     # 8 hours
        "export_formats": ["csv", "json", "pdf"],
    },
    "analyst": {
        "display_name": "Data Analyst",
        "capabilities": [
            "view_all_data",
            "view_sensitive_data",
            "export_data",
            "create_app",
            "modify_app",
        ],
        "max_rows_per_query": 100000,
        "max_components_per_app": 6,
        "allowed_component_types": None,    # All types
        "can_use_templates": True,
        "session_timeout_minutes": 240,     # 4 hours
        "export_formats": ["csv", "json"],
    },
    "viewer": {
        "display_name": "Viewer",
        "capabilities": [
            "view_all_data",
        ],
        "max_rows_per_query": 10000,
        "max_components_per_app": 4,
        "allowed_component_types": [
            "bar_chart", "line_chart", "pie_chart",
            "kpi_card", "metric_highlight",
        ],  # No table or scatter_plot (can't see raw data)
        "can_use_templates": False,
        "session_timeout_minutes": 60,      # 1 hour
        "export_formats": [],               # No export
    },
}
```

### 1.2 Update `config.py` — Column Sensitivity Classification

Add a new config section that classifies which columns are sensitive, so governance can enforce column-level access control:

```python
# ============================================================================
# DATA SENSITIVITY CLASSIFICATION
# ============================================================================

COLUMN_SENSITIVITY = {
    # Public — all roles can see
    "public": [
        "order_id", "order_date", "region", "product", "category",
        "shipping_mode", "quantity",
    ],
    # Internal — analyst and admin only
    "internal": [
        "unit_cost", "total_cost", "shipping_cost", "warehouse_cost",
        "defect_rate",
    ],
    # Restricted — admin only
    "restricted": [
        "supplier",  # Supplier names are business-sensitive
    ],
}

# Reverse lookup: column → sensitivity level
COLUMN_SENSITIVITY_MAP = {}
for level, columns in COLUMN_SENSITIVITY.items():
    for col in columns:
        COLUMN_SENSITIVITY_MAP[col] = level

# Which roles can access which sensitivity levels
SENSITIVITY_ACCESS = {
    "admin": ["public", "internal", "restricted"],
    "analyst": ["public", "internal"],
    "viewer": ["public"],
}
```

### 1.3 Update `config.py` — SQL Blocklist

```python
# ============================================================================
# SQL SECURITY
# ============================================================================

# SQL keywords that should NEVER appear in generated queries
SQL_BLOCKLIST = [
    "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE",
    "TRUNCATE", "EXEC", "EXECUTE", "GRANT", "REVOKE",
    "UNION",  # Prevent UNION injection
    "INTO OUTFILE", "INTO DUMPFILE",  # File write attempts
    "LOAD_EXTENSION",  # DuckDB-specific: prevent loading extensions
]

# Max query length (characters) — prevents prompt injection via massive queries
MAX_QUERY_LENGTH = 2000
```

---

## SECTION 2: DEEPEN `engine/governance.py`

Replace the entire governance.py with a comprehensive implementation. Every function below either replaces a skeleton function or is new.

### 2.1 SQL Sanitization (NEW — runs BEFORE execution)

```python
def sanitize_sql(sql_query: str) -> Dict[str, Any]:
    """
    Check SQL query for dangerous keywords BEFORE execution.
    This is a pre-execution gate — if it fails, the query must NOT run.

    Args:
        sql_query: SQL query to check

    Returns:
        {
            "safe": bool,
            "blocked_keywords": List[str],  # Which keywords were found
            "query_length_ok": bool,
            "details": str
        }
    """
```

Implementation:
- Check `sql_query.upper()` against every keyword in `SQL_BLOCKLIST`
- Use word boundary matching, not substring (so "UPDATE" doesn't flag "UPDATED_AT")
- Check query length against `MAX_QUERY_LENGTH`
- Return immediately on first blocked keyword
- Log the attempt to audit trail

### 2.2 Column-Level Access Control (NEW)

```python
def check_column_access(sql_query: str, role: str) -> Dict[str, Any]:
    """
    Check if the role has access to all columns referenced in the SQL query.

    Parses column names from SQL (SELECT clause and WHERE clause),
    checks each against COLUMN_SENSITIVITY_MAP and SENSITIVITY_ACCESS.

    Args:
        sql_query: SQL query to check
        role: User role

    Returns:
        {
            "allowed": bool,
            "blocked_columns": List[str],       # Columns the role can't access
            "column_details": List[Dict],       # Per-column breakdown
            "redaction_needed": bool             # True if some columns should be masked
        }
    """
```

Implementation:
- Extract column names from SQL using regex (look for column names after SELECT and in WHERE)
- Cross-reference each column against `COLUMN_SENSITIVITY_MAP`
- Check if the role has access to that sensitivity level via `SENSITIVITY_ACCESS`
- For viewers: if query references `internal` or `restricted` columns, set `allowed=False`
- Return the list of blocked columns so the frontend can show a meaningful error

### 2.3 Component Type Enforcement (NEW)

```python
def check_component_permissions(app_definition: Dict, role: str) -> Dict[str, Any]:
    """
    Check if the role is allowed to use all component types in the app.

    Viewers can't use tables or scatter_plots (raw data exposure).
    Also enforces max_components_per_app per role.

    Returns:
        {
            "allowed": bool,
            "blocked_components": List[Dict],   # {id, type, reason}
            "component_count_ok": bool,
            "max_allowed": int
        }
    """
```

### 2.4 Real Data Quality Checks (REPLACE skeleton)

```python
def _check_data_quality(execution_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Actually analyze execution results for data quality issues.

    Checks:
    - Null/NaN values in any column
    - Duplicate rows
    - Outliers (values > 3 standard deviations from mean for numeric columns)
    - Empty string values
    - Data type consistency

    Returns:
        {
            "overall_quality": "good" | "warning" | "poor",
            "null_count": int,
            "duplicate_count": int,
            "outlier_count": int,
            "issues": List[str],
            "per_component": Dict[str, Dict]  # Quality per component
        }
    """
```

Implementation:
- Loop through each component result
- If result has `data` key (list of dicts), convert to DataFrame for analysis
- Count nulls: `df.isnull().sum().sum()`
- Count duplicates: `df.duplicated().sum()`
- For numeric columns: flag values where `abs(val - mean) > 3 * std`
- Set overall_quality based on thresholds: 0 issues = "good", 1-3 = "warning", 4+ = "poor"

### 2.5 Persistent Audit Trail (REPLACE placeholder)

```python
import json
from datetime import datetime
from pathlib import Path

AUDIT_LOG_PATH = Path("audit_trail.jsonl")

def _log_audit_trail(action: str, details: Dict[str, Any]) -> None:
    """
    Write governance events to a persistent JSONL audit log.

    Each line is a JSON object with:
    - timestamp: ISO 8601
    - action: What happened
    - role: Who did it
    - details: Full context
    - governance_result: pass/fail

    Person 2 can render this in the UI as an audit trail table.
    """
```

Implementation:
- Create a JSONL file (one JSON object per line, append-only)
- Each entry includes: `timestamp`, `action`, `details`, `session_id` (use a UUID generated at module load)
- Append to file, don't overwrite
- Also keep an in-memory list for the current session so Person 2 can access without reading the file

Add a public function for the frontend:

```python
def get_audit_trail(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Return the most recent audit trail entries.
    Person 2 calls this to render the audit trail in the UI.
    """
```

### 2.6 Enhanced PII Detection (IMPROVE existing)

Improve `_detect_pii` to also scan execution results, not just SQL queries:

```python
def _detect_pii(text: str, scan_data: bool = False, data: List[Dict] = None) -> List[Dict[str, Any]]:
    """
    Scan text AND optionally data rows for PII.

    When scan_data=True, also scans actual cell values in execution results.
    This catches PII that exists in the data itself, not just the query.
    """
```

Implementation:
- Keep existing SQL query scanning
- Add: if `scan_data` and `data` provided, iterate through each row's values and scan for PII patterns
- For each PII found in data, include `source: "data"` vs `source: "query"` in the result
- Admin role with `view_pii` capability can see PII data; others get it redacted

### 2.7 PII Redaction (NEW)

```python
def redact_pii(execution_results: Dict[str, Any], role: str) -> Dict[str, Any]:
    """
    Redact PII from execution results based on role.

    Admins with view_pii: see raw data
    Everyone else: PII values replaced with [REDACTED]

    Returns a COPY of execution_results with PII redacted.
    Does not modify the original.
    """
```

### 2.8 Updated `run_governance_checks` (REPLACE)

The main function needs to orchestrate all new checks:

```python
def run_governance_checks(
    app_definition: Dict[str, Any],
    role: str = "analyst",
    execution_results: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Run comprehensive governance checks.

    Order of operations:
    1. SQL Sanitization (pre-execution safety)
    2. Column-level access control
    3. Component type permissions
    4. PII detection (queries + data)
    5. Role-based access control
    6. Query complexity analysis
    7. Data quality checks
    8. Export control
    9. Audit trail logging

    Returns:
        {
            "passed": bool,
            "role": str,
            "role_display_name": str,
            "sql_safety": Dict,
            "column_access": Dict,
            "component_permissions": Dict,
            "pii_detected": List,
            "pii_redacted": bool,
            "access_granted": bool,
            "query_complexity": Dict,
            "data_quality": Dict,
            "export_allowed": bool,
            "export_formats": List[str],
            "warnings": List[str],
            "blocked_reasons": List[str],   # Hard blocks (vs warnings)
            "audit_entry_id": str,
        }
    """
```

---

## SECTION 3: PRE-EXECUTION GOVERNANCE GATE IN PIPELINE

Update `engine/pipeline.py` to run governance BEFORE executing SQL, not just after. This is the key architectural change — governance can **block** dangerous queries from ever touching DuckDB.

### 3.1 Updated `run_pipeline`

```python
def run_pipeline(
    user_message: str,
    existing_app: Optional[Dict[str, Any]] = None,
    filters: Optional[Dict[str, Any]] = None,
    role: str = "analyst",
) -> Dict[str, Any]:
    """
    Full StackForge pipeline with governance gates.

    NEW FLOW:
    1. Parse intent → app_definition
    2. PRE-EXECUTION GOVERNANCE:
       a. Sanitize all SQL queries (block DROP, DELETE, etc.)
       b. Check column access for role
       c. Check component type permissions
       d. If any hard block → return error with blocked_reasons, do NOT execute
    3. Execute SQL queries (only if governance pre-check passed)
    4. POST-EXECUTION GOVERNANCE:
       a. PII detection on actual data
       b. PII redaction for non-admin roles
       c. Data quality checks
       d. Export control
    5. Validate and generate explanations
    6. Log audit trail
    7. Return full result
    """
```

When pre-execution governance fails, the return should be:

```python
{
    "app_definition": app_definition,
    "execution_results": {},           # Empty — blocked
    "validation": {
        "overall_status": "blocked",
        "components": [],
        "total_warnings": 0,
    },
    "governance": governance_result,   # Contains blocked_reasons
}
```

Person 2 checks `governance["passed"]` — if `False` and `blocked_reasons` is non-empty, they show an access denied message instead of charts.

---

## SECTION 4: TEST SUITE — `tests/test_governance.py`

Add these tests to the existing test file. All existing tests must still pass.

### 4.1 SQL Sanitization Tests

```python
def test_sql_sanitization_blocks_drop():
    """DROP TABLE must be blocked."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("DROP TABLE supply_chain")
    assert result["safe"] == False
    assert "DROP" in result["blocked_keywords"]

def test_sql_sanitization_blocks_delete():
    from engine.governance import sanitize_sql
    result = sanitize_sql("DELETE FROM supply_chain WHERE 1=1")
    assert result["safe"] == False

def test_sql_sanitization_blocks_union_injection():
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT * FROM supply_chain UNION SELECT * FROM users")
    assert result["safe"] == False

def test_sql_sanitization_allows_normal_query():
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier")
    assert result["safe"] == True

def test_sql_sanitization_query_length():
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT " + "a," * 1000 + "b FROM supply_chain")
    assert result["query_length_ok"] == False

def test_sql_sanitization_word_boundary():
    """'UPDATED_AT' should NOT trigger the UPDATE blocklist."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT updated_at FROM supply_chain")
    assert result["safe"] == True
```

### 4.2 Column Access Tests

```python
def test_viewer_blocked_from_cost_columns():
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT region, total_cost FROM supply_chain",
        role="viewer"
    )
    assert result["allowed"] == False
    assert "total_cost" in result["blocked_columns"]

def test_viewer_allowed_public_columns():
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT region, product, category FROM supply_chain",
        role="viewer"
    )
    assert result["allowed"] == True

def test_analyst_allowed_internal_columns():
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT region, total_cost, defect_rate FROM supply_chain",
        role="analyst"
    )
    assert result["allowed"] == True

def test_analyst_blocked_from_restricted():
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT supplier, total_cost FROM supply_chain",
        role="analyst"
    )
    assert result["allowed"] == False
    assert "supplier" in result["blocked_columns"]

def test_admin_sees_everything():
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT supplier, total_cost, defect_rate FROM supply_chain",
        role="admin"
    )
    assert result["allowed"] == True
```

### 4.3 Component Permission Tests

```python
def test_viewer_blocked_from_table():
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": "t1", "type": "table", "title": "Data"},
        ]
    }
    result = check_component_permissions(app, role="viewer")
    assert result["allowed"] == False
    assert any(c["type"] == "table" for c in result["blocked_components"])

def test_viewer_allowed_bar_chart():
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": "c1", "type": "bar_chart", "title": "Chart"},
        ]
    }
    result = check_component_permissions(app, role="viewer")
    assert result["allowed"] == True

def test_viewer_max_components():
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": f"c{i}", "type": "bar_chart", "title": f"Chart {i}"}
            for i in range(5)  # Viewer max is 4
        ]
    }
    result = check_component_permissions(app, role="viewer")
    assert result["component_count_ok"] == False

def test_admin_unlimited_components():
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": f"c{i}", "type": "table", "title": f"Table {i}"}
            for i in range(8)
        ]
    }
    result = check_component_permissions(app, role="admin")
    assert result["allowed"] == True
    assert result["component_count_ok"] == True
```

### 4.4 Data Quality Tests

```python
def test_data_quality_detects_nulls():
    from engine.governance import _check_data_quality
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"supplier": "Acme", "cost": 100},
                {"supplier": None, "cost": 200},
            ],
            "row_count": 2,
        }
    }
    quality = _check_data_quality(results)
    assert quality["null_count"] > 0
    assert quality["overall_quality"] in ["warning", "poor"]

def test_data_quality_good_data():
    from engine.governance import _check_data_quality
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"supplier": "Acme", "cost": 100},
                {"supplier": "BuildRight", "cost": 200},
            ],
            "row_count": 2,
        }
    }
    quality = _check_data_quality(results)
    assert quality["overall_quality"] == "good"
```

### 4.5 Audit Trail Tests

```python
def test_audit_trail_writes_entry():
    from engine.governance import _log_audit_trail, get_audit_trail
    _log_audit_trail("test_action", {"test": True})
    trail = get_audit_trail(limit=1)
    assert len(trail) >= 1
    assert trail[-1]["action"] == "test_action"

def test_audit_trail_includes_timestamp():
    from engine.governance import get_audit_trail
    trail = get_audit_trail(limit=1)
    assert "timestamp" in trail[-1]
```

### 4.6 PII Redaction Tests

```python
def test_pii_redacted_for_analyst():
    from engine.governance import redact_pii
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"name": "john@acme.com", "cost": 100},
            ],
            "row_count": 1,
        }
    }
    redacted = redact_pii(results, role="analyst")
    assert "[REDACTED]" in str(redacted["chart_1"]["data"])

def test_pii_visible_for_admin():
    from engine.governance import redact_pii
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"name": "john@acme.com", "cost": 100},
            ],
            "row_count": 1,
        }
    }
    redacted = redact_pii(results, role="admin")
    assert "john@acme.com" in str(redacted["chart_1"]["data"])
```

### 4.7 Pre-Execution Gate Integration Tests

```python
def test_pipeline_blocks_viewer_from_creating():
    """Viewers can't create apps — pipeline should return blocked result."""
    from engine.pipeline import run_pipeline
    result = run_pipeline("Show me costs", role="viewer")
    assert result["governance"]["access_granted"] == False
    assert result["governance"]["passed"] == False

def test_pipeline_blocks_dangerous_sql():
    """If GPT somehow generates dangerous SQL, governance gate catches it."""
    from engine.governance import sanitize_sql
    # Simulate what would happen
    result = sanitize_sql("SELECT * FROM supply_chain; DROP TABLE supply_chain")
    assert result["safe"] == False
```

---

## SECTION 5: WHAT THE FRONTEND RECEIVES (for Person 2)

After governance deepening, Person 2's `result["governance"]` object is much richer:

```python
# When governance PASSES (admin or analyst with safe queries):
{
    "passed": True,
    "role": "analyst",
    "role_display_name": "Data Analyst",
    "sql_safety": {"safe": True, "blocked_keywords": []},
    "column_access": {"allowed": True, "blocked_columns": []},
    "component_permissions": {"allowed": True, "blocked_components": []},
    "pii_detected": [],
    "pii_redacted": False,
    "access_granted": True,
    "query_complexity": {"chart_1": {"is_complex": False}},
    "data_quality": {"overall_quality": "good", "null_count": 0},
    "export_allowed": True,
    "export_formats": ["csv", "json"],
    "warnings": [],
    "blocked_reasons": [],
    "audit_entry_id": "a1b2c3d4"
}

# When governance BLOCKS (viewer trying to create app):
{
    "passed": False,
    "role": "viewer",
    "role_display_name": "Viewer",
    "sql_safety": {},          # Didn't get this far
    "column_access": {},
    "component_permissions": {},
    "pii_detected": [],
    "pii_redacted": False,
    "access_granted": False,
    "query_complexity": {},
    "data_quality": {},
    "export_allowed": False,
    "export_formats": [],
    "warnings": [],
    "blocked_reasons": ["Role 'viewer' does not have 'create_app' capability"],
    "audit_entry_id": "e5f6g7h8"
}
```

Person 2 renders this as:
- Green shield icon + "All checks passed" when `passed=True`
- Red shield + blocked_reasons list when `passed=False`
- Yellow warnings when `passed=True` but `warnings` is non-empty
- Audit trail table from `get_audit_trail()`

---

## SECTION 6: TIMELINE

### Phase 1 (30 min): Config Updates
- Update ROLES in config.py
- Add COLUMN_SENSITIVITY, COLUMN_SENSITIVITY_MAP, SENSITIVITY_ACCESS
- Add SQL_BLOCKLIST, MAX_QUERY_LENGTH
- Run existing tests → all must still pass

### Phase 2 (45 min): New Governance Functions
- Implement `sanitize_sql()`
- Implement `check_column_access()`
- Implement `check_component_permissions()`
- Implement real `_check_data_quality()`
- Write tests as you go

### Phase 3 (30 min): Audit Trail + PII
- Replace `_log_audit_trail()` with persistent JSONL writer
- Add `get_audit_trail()` public function
- Enhance `_detect_pii()` to scan data rows
- Implement `redact_pii()`
- Write tests

### Phase 4 (30 min): Pipeline Integration
- Update `run_pipeline()` with pre-execution governance gate
- Update `run_governance_checks()` to orchestrate all new checks
- Write integration tests

### Phase 5 (15 min): Verify Everything
- Run `pytest tests/ -v` → all old + new tests pass
- Run 3 manual tests: admin, analyst, viewer roles through pipeline
- Verify audit_trail.jsonl is being written

**Total: ~2.5 hours**

---

## CLAUDE CODE PROMPT

```
Read GOVERNANCE-DEEPENING.md — it is your complete PRD for this task. Follow it exactly.

You are on the `engine` branch. You will modify:
- config.py (new ROLES structure, COLUMN_SENSITIVITY, SQL_BLOCKLIST)
- engine/governance.py (deepen every function, add new ones)
- engine/pipeline.py (add pre-execution governance gate)
- tests/test_governance.py (add all new tests)

Follow the phases in order. After each phase, run `pytest tests/ -v` to make sure nothing is broken.

CRITICAL: Do NOT modify intent_parser.py, executor.py, or validator.py. They are complete and passing. Do NOT touch anything in ui/.

When done, run the full test suite and print results. Then run 3 manual pipeline calls (one per role: admin, analyst, viewer) and show the governance output for each.
```
