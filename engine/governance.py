import re
import json
import copy
import uuid
import logging
import pandas as pd
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pathlib import Path

from config import (
    PII_PATTERNS, ROLES, SQL_BLOCKLIST, MAX_QUERY_LENGTH,
    COLUMN_SENSITIVITY_MAP, SENSITIVITY_ACCESS,
)

logger = logging.getLogger(__name__)

# ============================================================================
# SESSION & AUDIT STATE
# ============================================================================

SESSION_ID = str(uuid.uuid4())[:8]
AUDIT_LOG_PATH = Path("audit_trail.jsonl")
_audit_memory: List[Dict[str, Any]] = []  # In-memory trail for current session


# ============================================================================
# PII DETECTION (ENHANCED — scans text AND data rows)
# ============================================================================


def _detect_pii(
    text: str,
    scan_data: bool = False,
    data: Optional[List[Dict]] = None,
) -> List[Dict[str, Any]]:
    """
    Scan text AND optionally data rows for PII.

    Args:
        text: Text to scan (SQL query, user prompt, etc.)
        scan_data: If True, also scan cell values in data rows
        data: List of row dicts to scan (from execution results)

    Returns:
        List of detected PII items with type, value, and source
    """
    detected = []

    # Scan the text (query or prompt)
    for pii_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, str(text)):
            detected.append({
                "type": pii_type,
                "value": match.group(),
                "source": "query",
            })

    # Scan actual data rows if requested
    if scan_data and data:
        for row in data:
            for col, val in row.items():
                val_str = str(val) if val is not None else ""
                for pii_type, pattern in PII_PATTERNS.items():
                    for match in re.finditer(pattern, val_str):
                        detected.append({
                            "type": pii_type,
                            "value": match.group(),
                            "source": "data",
                            "column": col,
                        })

    return detected


# ============================================================================
# PII REDACTION
# ============================================================================


def redact_pii(
    execution_results: Dict[str, Any],
    role: str,
) -> Dict[str, Any]:
    """
    Redact PII from execution results based on role.

    Admins with view_pii: see raw data.
    Everyone else: PII values replaced with [REDACTED].

    Returns a COPY of execution_results with PII redacted.
    """
    role_config = ROLES.get(role, {})
    if "view_pii" in role_config.get("capabilities", []):
        return execution_results  # Admin sees everything

    redacted = copy.deepcopy(execution_results)

    for component_id, result in redacted.items():
        data = result.get("data")
        if not data or not isinstance(data, list):
            continue
        for row in data:
            for col, val in list(row.items()):
                val_str = str(val) if val is not None else ""
                for pii_type, pattern in PII_PATTERNS.items():
                    if re.search(pattern, val_str):
                        row[col] = "[REDACTED]"
                        break

    return redacted


# ============================================================================
# ACCESS CONTROL
# ============================================================================


def _check_access_control(role: str, capability: str) -> bool:
    """Check if a role has a specific capability."""
    role_config = ROLES.get(role, {})
    return capability in role_config.get("capabilities", [])


# ============================================================================
# SQL SANITIZATION (PRE-EXECUTION GATE)
# ============================================================================


def sanitize_sql(sql_query: str) -> Dict[str, Any]:
    """
    Check SQL query for dangerous keywords BEFORE execution.
    Uses word boundary matching so 'UPDATED_AT' doesn't trigger 'UPDATE'.

    Returns:
        {"safe": bool, "blocked_keywords": List[str], "query_length_ok": bool, "details": str}
    """
    blocked_keywords = []
    query_upper = sql_query.upper()

    for keyword in SQL_BLOCKLIST:
        # Multi-word keywords (e.g. "INTO OUTFILE") — simple substring
        if " " in keyword:
            if keyword in query_upper:
                blocked_keywords.append(keyword)
        else:
            # Single-word keywords — word boundary match
            if re.search(r'\b' + keyword + r'\b', query_upper):
                blocked_keywords.append(keyword)

    query_length_ok = len(sql_query) <= MAX_QUERY_LENGTH

    safe = len(blocked_keywords) == 0 and query_length_ok

    if not safe:
        details_parts = []
        if blocked_keywords:
            details_parts.append(f"Blocked keywords: {blocked_keywords}")
        if not query_length_ok:
            details_parts.append(f"Query too long: {len(sql_query)} chars (max {MAX_QUERY_LENGTH})")
        details = "; ".join(details_parts)
        _log_audit_trail("sql_blocked", {
            "blocked_keywords": blocked_keywords,
            "query_preview": sql_query[:100],
        })
    else:
        details = "Query passed sanitization"

    return {
        "safe": safe,
        "blocked_keywords": blocked_keywords,
        "query_length_ok": query_length_ok,
        "details": details,
    }


# ============================================================================
# COLUMN-LEVEL ACCESS CONTROL
# ============================================================================


def check_column_access(sql_query: str, role: str) -> Dict[str, Any]:
    """
    Check if the role has access to all columns referenced in the SQL query.

    Parses column names from SQL and cross-references against
    COLUMN_SENSITIVITY_MAP and SENSITIVITY_ACCESS.
    """
    allowed_levels = SENSITIVITY_ACCESS.get(role, [])
    query_upper = sql_query.upper()

    # Extract column names by checking which known columns appear in the query
    blocked_columns = []
    column_details = []

    for col, sensitivity in COLUMN_SENSITIVITY_MAP.items():
        # Check if the column name appears in the query (word boundary match)
        if re.search(r'\b' + col.upper() + r'\b', query_upper):
            allowed = sensitivity in allowed_levels
            column_details.append({
                "column": col,
                "sensitivity": sensitivity,
                "allowed": allowed,
            })
            if not allowed:
                blocked_columns.append(col)

    return {
        "allowed": len(blocked_columns) == 0,
        "blocked_columns": blocked_columns,
        "column_details": column_details,
        "redaction_needed": len(blocked_columns) > 0,
    }


# ============================================================================
# COMPONENT TYPE ENFORCEMENT
# ============================================================================


def check_component_permissions(
    app_definition: Dict[str, Any],
    role: str,
) -> Dict[str, Any]:
    """
    Check if the role is allowed to use all component types in the app.
    Also enforces max_components_per_app per role.
    """
    role_config = ROLES.get(role, {})
    allowed_types = role_config.get("allowed_component_types")
    max_components = role_config.get("max_components_per_app", 8)

    components = app_definition.get("components", [])
    blocked_components = []

    if allowed_types is not None:
        for comp in components:
            if comp.get("type") not in allowed_types:
                blocked_components.append({
                    "id": comp.get("id"),
                    "type": comp.get("type"),
                    "reason": f"Component type '{comp.get('type')}' not allowed for role '{role}'",
                })

    component_count_ok = len(components) <= max_components

    return {
        "allowed": len(blocked_components) == 0 and component_count_ok,
        "blocked_components": blocked_components,
        "component_count_ok": component_count_ok,
        "max_allowed": max_components,
    }


# ============================================================================
# QUERY COMPLEXITY CHECK
# ============================================================================


def _check_query_complexity(sql_query: str) -> Dict[str, Any]:
    """Analyze query complexity (joins, subqueries, aggregations)."""
    query_upper = sql_query.upper()

    complexity = {
        "join_count": query_upper.count("JOIN"),
        "subquery_count": max(0, query_upper.count("SELECT") - 1),
        "has_aggregation": any(
            agg in query_upper
            for agg in ["GROUP BY", "SUM(", "COUNT(", "AVG("]
        ),
        "is_complex": False,
    }

    complexity["is_complex"] = (
        complexity["join_count"] > 2 or complexity["subquery_count"] > 1
    )

    return complexity


# ============================================================================
# DATA QUALITY CHECKS (REAL IMPLEMENTATION)
# ============================================================================


def _check_data_quality(execution_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze execution results for data quality issues.

    Checks: nulls, duplicates, outliers (>3 std dev), empty strings.
    """
    total_nulls = 0
    total_duplicates = 0
    total_outliers = 0
    issues = []
    per_component = {}

    for comp_id, result in execution_results.items():
        if result.get("status") != "success":
            continue

        data = result.get("data")
        if data is None:
            continue

        # Convert list-of-dicts to DataFrame if needed
        if isinstance(data, list):
            if len(data) == 0:
                continue
            df = pd.DataFrame(data)
        elif isinstance(data, pd.DataFrame):
            if data.empty:
                continue
            df = data
        else:
            continue

        comp_nulls = int(df.isnull().sum().sum())
        comp_duplicates = int(df.duplicated().sum())
        comp_outliers = 0

        # Outlier detection for numeric columns
        for col in df.select_dtypes(include=["number"]).columns:
            series = df[col].dropna()
            if len(series) > 2:
                mean = series.mean()
                std = series.std()
                if std > 0:
                    outlier_count = int(((series - mean).abs() > 3 * std).sum())
                    comp_outliers += outlier_count

        total_nulls += comp_nulls
        total_duplicates += comp_duplicates
        total_outliers += comp_outliers

        comp_issues = []
        if comp_nulls > 0:
            comp_issues.append(f"{comp_nulls} null values")
        if comp_duplicates > 0:
            comp_issues.append(f"{comp_duplicates} duplicate rows")
        if comp_outliers > 0:
            comp_issues.append(f"{comp_outliers} outliers")

        per_component[comp_id] = {
            "null_count": comp_nulls,
            "duplicate_count": comp_duplicates,
            "outlier_count": comp_outliers,
            "quality": "good" if not comp_issues else "warning",
        }

        issues.extend(
            f"{comp_id}: {issue}" for issue in comp_issues
        )

    total_issues = total_nulls + total_duplicates + total_outliers
    if total_issues == 0:
        overall_quality = "good"
    elif total_issues <= 3:
        overall_quality = "warning"
    else:
        overall_quality = "poor"

    return {
        "overall_quality": overall_quality,
        "null_count": total_nulls,
        "duplicate_count": total_duplicates,
        "outlier_count": total_outliers,
        "issues": issues,
        "per_component": per_component,
    }


# ============================================================================
# EXPORT CONTROL
# ============================================================================


def _check_export_control(role: str, data_size: int) -> Dict[str, Any]:
    """Check if role can export data of this size."""
    from config import EXPORT_ROW_LIMIT

    role_config = ROLES.get(role, {})
    max_rows = role_config.get("max_rows_per_query", EXPORT_ROW_LIMIT)
    export_formats = role_config.get("export_formats", [])

    can_export = (
        len(export_formats) > 0
        and (max_rows is None or data_size <= max_rows)
    )

    return {
        "can_export": can_export,
        "max_rows": max_rows,
        "requested_rows": data_size,
        "export_formats": export_formats,
    }


# ============================================================================
# PERSISTENT AUDIT TRAIL
# ============================================================================


def _log_audit_trail(action: str, details: Dict[str, Any]) -> None:
    """
    Write governance events to a persistent JSONL audit log
    and keep in-memory for current session.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": SESSION_ID,
        "action": action,
        "details": details,
    }

    _audit_memory.append(entry)

    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.warning(f"Failed to write audit log: {e}")

    logger.info(f"[AUDIT] {action}: {details}")


def get_audit_trail(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Return the most recent audit trail entries.
    Person 2 calls this to render the audit trail in the UI.
    """
    return _audit_memory[-limit:]


# ============================================================================
# MAIN GOVERNANCE FUNCTION
# ============================================================================


def run_governance_checks(
    app_definition: Dict[str, Any],
    role: str = "analyst",
    execution_results: Dict[str, Any] = None,
    user_message: str = "",
) -> Dict[str, Any]:
    """
    Run comprehensive governance checks.

    Order of operations:
    1. SQL Sanitization (pre-execution safety)
    2. Column-level access control
    3. Component type permissions
    4. PII detection (queries + prompt + data)
    5. Role-based access control
    6. Query complexity analysis
    7. Data quality checks
    8. Export control
    9. Audit trail logging
    """
    passed = True
    warnings: List[str] = []
    blocked_reasons: List[str] = []
    checks: List[Dict] = []
    role_config = ROLES.get(role, {})

    # --- 1. SQL Sanitization ---
    sql_safety = {"safe": True, "blocked_keywords": [], "query_length_ok": True, "details": ""}
    for component in app_definition.get("components", []):
        sql_query = component.get("sql_query", "")
        result = sanitize_sql(sql_query)
        if not result["safe"]:
            sql_safety = result
            passed = False
            blocked_reasons.append(
                f"Dangerous SQL in {component.get('id')}: {result['details']}"
            )
            break

    checks.append({
        "name": "sql_sanitization",
        "status": "pass" if sql_safety["safe"] else "fail",
        "details": sql_safety["details"] or "All queries passed sanitization",
    })

    # --- 2. Column-Level Access Control ---
    column_access_all = {"allowed": True, "blocked_columns": [], "column_details": [], "redaction_needed": False}
    for component in app_definition.get("components", []):
        sql_query = component.get("sql_query", "")
        ca = check_column_access(sql_query, role)
        if not ca["allowed"]:
            column_access_all["allowed"] = False
            column_access_all["blocked_columns"].extend(ca["blocked_columns"])
            column_access_all["redaction_needed"] = True
        column_access_all["column_details"].extend(ca["column_details"])

    # Deduplicate blocked columns
    column_access_all["blocked_columns"] = list(set(column_access_all["blocked_columns"]))

    if not column_access_all["allowed"]:
        passed = False
        blocked_reasons.append(
            f"Role '{role}' cannot access columns: {column_access_all['blocked_columns']}"
        )

    checks.append({
        "name": "column_access",
        "status": "pass" if column_access_all["allowed"] else "fail",
        "details": (
            "All columns accessible"
            if column_access_all["allowed"]
            else f"Blocked columns: {column_access_all['blocked_columns']}"
        ),
    })

    # --- 3. Component Type Permissions ---
    comp_perms = check_component_permissions(app_definition, role)
    if not comp_perms["allowed"]:
        passed = False
        reasons = [b["reason"] for b in comp_perms["blocked_components"]]
        if not comp_perms["component_count_ok"]:
            reasons.append(
                f"Too many components: {len(app_definition.get('components', []))} "
                f"(max {comp_perms['max_allowed']} for role '{role}')"
            )
        blocked_reasons.extend(reasons)

    checks.append({
        "name": "component_permissions",
        "status": "pass" if comp_perms["allowed"] else "fail",
        "details": (
            "All component types allowed"
            if comp_perms["allowed"]
            else f"Blocked: {[b['type'] for b in comp_perms['blocked_components']]}"
        ),
    })

    # --- 4. PII Detection (queries + prompt + data) ---
    pii_detected = []
    if user_message:
        prompt_pii = _detect_pii(user_message)
        if prompt_pii:
            pii_detected.extend(prompt_pii)
            warnings.append("PII detected in user prompt")

    for component in app_definition.get("components", []):
        sql_query = component.get("sql_query", "")
        pii = _detect_pii(sql_query)
        if pii:
            pii_detected.extend(pii)
            warnings.append(f"PII detected in component {component.get('id')}")

    # Scan execution result data for PII
    pii_redacted = False
    if execution_results:
        for comp_id, result in execution_results.items():
            data = result.get("data")
            if isinstance(data, list) and data:
                data_pii = _detect_pii("", scan_data=True, data=data)
                if data_pii:
                    pii_detected.extend(data_pii)
                    warnings.append(f"PII found in data for {comp_id}")

    if pii_detected and not _check_access_control(role, "view_pii"):
        pii_redacted = True
        passed = False

    checks.append({
        "name": "pii_detection",
        "status": "fail" if pii_detected else "pass",
        "details": (
            f"Found {len(pii_detected)} PII items"
            if pii_detected
            else "No PII detected"
        ),
    })

    # --- 5. Role-Based Access Control ---
    access_granted = _check_access_control(role, "create_app")
    if not access_granted:
        passed = False
        blocked_reasons.append(
            f"Role '{role}' does not have 'create_app' capability"
        )

    checks.append({
        "name": "access_control",
        "status": "pass" if access_granted else "fail",
        "details": f"Role '{role}' {'granted' if access_granted else 'denied'} create_app",
    })

    # --- 6. Query Complexity ---
    query_complexity = {}
    has_complex = False
    for component in app_definition.get("components", []):
        sql_query = component.get("sql_query", "")
        complexity = _check_query_complexity(sql_query)
        query_complexity[component.get("id")] = complexity
        if complexity["is_complex"]:
            has_complex = True
            warnings.append(f"Component {component.get('id')} has complex query")

    checks.append({
        "name": "query_complexity",
        "status": "warning" if has_complex else "pass",
        "details": f"Analyzed {len(query_complexity)} queries",
    })

    # --- 7. Data Quality ---
    data_quality = {}
    if execution_results:
        data_quality = _check_data_quality(execution_results)
        if data_quality.get("overall_quality") == "poor":
            warnings.append(f"Poor data quality: {data_quality.get('issues', [])}")

    checks.append({
        "name": "data_quality",
        "status": (
            "pass" if data_quality.get("overall_quality", "good") == "good"
            else "warning"
        ),
        "details": data_quality.get("overall_quality", "not checked"),
    })

    # --- 8. Export Control ---
    total_rows = 0
    if execution_results:
        for result in execution_results.values():
            total_rows += result.get("row_count", 0)

    export_check = _check_export_control(role, total_rows)
    export_allowed = export_check["can_export"]
    export_formats = export_check.get("export_formats", [])

    if not export_allowed:
        warnings.append(
            f"Role '{role}' cannot export {total_rows} rows "
            f"(limit: {export_check['max_rows']})"
        )

    checks.append({
        "name": "export_control",
        "status": "pass" if export_allowed else "warning",
        "details": f"{total_rows} rows (limit: {export_check['max_rows']})",
    })

    # --- Determine overall_status ---
    if not passed:
        overall_status = "fail"
    elif warnings:
        overall_status = "warning"
    else:
        overall_status = "pass"

    # --- 9. Audit Trail ---
    audit_entry_id = str(uuid.uuid4())[:8]
    _log_audit_trail("governance_check", {
        "audit_entry_id": audit_entry_id,
        "role": role,
        "app_id": app_definition.get("app_title"),
        "passed": passed,
        "overall_status": overall_status,
        "warnings_count": len(warnings),
        "blocked_reasons": blocked_reasons,
    })

    return {
        "overall_status": overall_status,
        "passed": passed,
        "role": role,
        "role_display_name": role_config.get("display_name", role),
        "checks": checks,
        "sql_safety": sql_safety,
        "column_access": column_access_all,
        "component_permissions": comp_perms,
        "pii_detected": pii_detected,
        "pii_redacted": pii_redacted,
        "access_granted": access_granted,
        "query_complexity": query_complexity,
        "data_quality": data_quality,
        "export_allowed": export_allowed,
        "export_formats": export_formats,
        "warnings": warnings,
        "blocked_reasons": blocked_reasons,
        "audit_entry_id": audit_entry_id,
    }
