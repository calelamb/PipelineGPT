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
        "min_categories": 2,
        "max_categories": 12,
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
    if df is None:
        return f"{component_title}: No data available"
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
