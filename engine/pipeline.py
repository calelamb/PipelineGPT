import logging
from typing import Optional, Dict, Any

from data.sample_data_loader import get_connection, get_table_schema, get_all_sample_data
from engine.intent_parser import parse_intent
from engine.executor import execute_app_components
from engine.validator import validate_and_explain
from engine.governance import (
    run_governance_checks,
    sanitize_sql,
    check_column_access,
    check_component_permissions,
    redact_pii,
)
from engine.overview import generate_overview

logger = logging.getLogger(__name__)


def run_pipeline(
    user_message: str,
    existing_app: Optional[Dict[str, Any]] = None,
    filters: Optional[Dict[str, Any]] = None,
    role: str = "analyst",
) -> Dict[str, Any]:
    """
    Full StackForge pipeline with governance gates.

    Flow:
    1. Parse intent -> app_definition
    2. PRE-EXECUTION GOVERNANCE:
       a. Sanitize all SQL queries (block DROP, DELETE, etc.)
       b. Check column access for role
       c. Check component type permissions
       d. If any hard block -> return error with blocked_reasons, do NOT execute
    3. Execute SQL queries (only if governance pre-check passed)
    4. POST-EXECUTION GOVERNANCE:
       a. Full governance checks (PII, data quality, export, audit)
       b. PII redaction for non-admin roles
    5. Validate and generate explanations
    6. Return full result
    """
    conn = get_connection()

    # 1. Parse intent -> app_definition
    app_definition = parse_intent(
        user_message,
        existing_app=existing_app,
        table_schema=get_table_schema(conn),
        sample_data=get_all_sample_data(conn),
    )

    # 2. PRE-EXECUTION GOVERNANCE GATE
    pre_block = False
    blocked_reasons = []

    # 2a. SQL sanitization
    for component in app_definition.get("components", []):
        sql_result = sanitize_sql(component.get("sql_query", ""))
        if not sql_result["safe"]:
            pre_block = True
            blocked_reasons.append(
                f"Blocked SQL in {component.get('id')}: {sql_result['details']}"
            )

    # 2b. Column access
    for component in app_definition.get("components", []):
        col_result = check_column_access(component.get("sql_query", ""), role)
        if not col_result["allowed"]:
            pre_block = True
            blocked_reasons.append(
                f"Column access denied for role '{role}': {col_result['blocked_columns']}"
            )

    # 2c. Component type permissions
    comp_result = check_component_permissions(app_definition, role)
    if not comp_result["allowed"]:
        pre_block = True
        for b in comp_result["blocked_components"]:
            blocked_reasons.append(b["reason"])
        if not comp_result["component_count_ok"]:
            blocked_reasons.append(
                f"Too many components for role '{role}' "
                f"(max {comp_result['max_allowed']})"
            )

    # 2d. Access control — can this role create apps at all?
    from config import ROLES
    role_config = ROLES.get(role, {})
    if "create_app" not in role_config.get("capabilities", []):
        pre_block = True
        blocked_reasons.append(
            f"Role '{role}' does not have 'create_app' capability"
        )

    # If pre-execution governance fails, return blocked result
    if pre_block:
        governance = run_governance_checks(
            app_definition, role=role, user_message=user_message,
        )
        governance["blocked_reasons"] = blocked_reasons
        governance["passed"] = False
        governance["overall_status"] = "fail"

        return {
            "app_definition": app_definition,
            "execution_results": {},
            "validation": {
                "overall_status": "blocked",
                "components": [],
                "total_warnings": 0,
            },
            "governance": governance,
        }

    # 3. Execute SQL queries (governance pre-check passed)
    execution_results = execute_app_components(
        conn, app_definition, filters=filters
    )

    # 4. Validate and generate explanations
    validation = validate_and_explain(app_definition, execution_results)

    # 5. POST-EXECUTION GOVERNANCE (full checks with data)
    governance = run_governance_checks(
        app_definition,
        role=role,
        execution_results=execution_results,
        user_message=user_message,
    )

    # 6. Convert DataFrames to dicts for Streamlit/Plotly consumption
    for component_id, result in execution_results.items():
        if "data" in result and hasattr(result["data"], "to_dict"):
            result["data"] = result["data"].to_dict(orient="records")

    # 7. PII redaction for non-admin roles
    if governance.get("pii_redacted"):
        execution_results = redact_pii(execution_results, role)

    # 8. Generate plain-English narration of how the dashboard answers the request
    result = {
        "app_definition": app_definition,
        "execution_results": execution_results,
        "validation": validation,
        "governance": governance,
    }
    result["overview"] = generate_overview(user_message, result)

    return result
