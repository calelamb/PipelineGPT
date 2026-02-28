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
        app_definition, role=role, execution_results=execution_results,
        user_message=user_message,
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
