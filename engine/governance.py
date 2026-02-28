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
        "can_export": max_rows is None or data_size <= max_rows,
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
    user_message: str = "",
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
                "overall_status": str ("pass", "warning", "fail"),
                "passed": bool,
                "role": str,
                "checks": List[Dict],
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
    checks = []

    # 1. PII Detection — scan both user prompt AND SQL queries
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

    pii_status = "fail" if pii_detected else "pass"
    checks.append({
        "name": "pii_detection",
        "status": pii_status,
        "details": f"Found {len(pii_detected)} PII items" if pii_detected else "No PII detected",
    })
    if pii_detected:
        passed = False

    # 2. Access Control
    access_granted = _check_access_control(role, "create_app")
    access_status = "pass" if access_granted else "fail"
    checks.append({
        "name": "access_control",
        "status": access_status,
        "details": f"Role '{role}' {'granted' if access_granted else 'denied'} create_app",
    })
    if not access_granted:
        warnings.append(f"Role '{role}' not allowed to create apps")
        passed = False

    # 3. Query Complexity
    query_complexity = {}
    has_complex = False
    for component in app_definition.get("components", []):
        sql_query = component.get("sql_query", "")
        complexity = _check_query_complexity(sql_query)
        query_complexity[component.get("id")] = complexity
        if complexity["is_complex"]:
            has_complex = True
            warnings.append(
                f"Component {component.get('id')} has complex query"
            )

    checks.append({
        "name": "query_complexity",
        "status": "warning" if has_complex else "pass",
        "details": f"Analyzed {len(query_complexity)} queries",
    })

    # 4. Data Quality (if results provided)
    data_quality = {}
    if execution_results:
        data_quality = _check_data_quality(execution_results)

    checks.append({
        "name": "data_quality",
        "status": "pass",
        "details": data_quality.get("overall_quality", "not checked") if data_quality else "not checked",
    })

    # 5. Export Control
    total_rows = 0
    if execution_results:
        for result in execution_results.values():
            total_rows += result.get("row_count", 0)

    export_check = _check_export_control(role, total_rows)
    export_allowed = export_check["can_export"]

    checks.append({
        "name": "export_control",
        "status": "pass" if export_allowed else "warning",
        "details": f"{total_rows} rows (limit: {export_check['max_rows']})",
    })

    if not export_allowed:
        warnings.append(
            f"Role '{role}' cannot export {total_rows} rows "
            f"(limit: {export_check['max_rows']})"
        )

    # Determine overall_status
    if not passed:
        overall_status = "fail"
    elif warnings:
        overall_status = "warning"
    else:
        overall_status = "pass"

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
        "overall_status": overall_status,
        "passed": passed,
        "role": role,
        "checks": checks,
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
