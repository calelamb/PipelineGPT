"""Tests for engine/validator.py — validates result checking and explanation generation."""

import pytest
import pandas as pd


class TestValidateAndExplain:
    """validate_and_explain() must check results and generate explanations."""

    def test_returns_expected_structure(self, mock_app_definition, mock_execution_results):
        from engine.validator import validate_and_explain
        result = validate_and_explain(mock_app_definition, mock_execution_results)

        assert isinstance(result, dict)
        assert "overall_status" in result, "Missing 'overall_status'"
        assert result["overall_status"] in ["success", "warning", "error"], \
            f"Invalid status: {result['overall_status']}"

    def test_components_have_explanations(self, mock_app_definition, mock_execution_results):
        from engine.validator import validate_and_explain
        result = validate_and_explain(mock_app_definition, mock_execution_results)

        # Should have component-level results
        components = result.get("components", [])
        assert len(components) > 0, "Validation should produce component-level results"

        for comp in components:
            assert "explanation" in comp or "status" in comp, \
                f"Component validation missing explanation/status: {comp}"

    def test_empty_data_produces_warning(self):
        from engine.validator import validate_and_explain

        app_def = {
            "components": [{
                "id": "empty_comp",
                "type": "bar_chart",
                "title": "Empty Chart",
                "sql_query": "SELECT 1 WHERE 1=0",
                "config": {},
                "width": "full"
            }]
        }
        results = {
            "empty_comp": {
                "status": "success",
                "data": pd.DataFrame(),
                "row_count": 0
            }
        }
        validation = validate_and_explain(app_def, results)
        assert validation["overall_status"] != "success", \
            "Empty results should not be 'success'"

    def test_error_result_detected(self):
        from engine.validator import validate_and_explain

        app_def = {
            "components": [{
                "id": "error_comp",
                "type": "table",
                "title": "Failed Query",
                "sql_query": "SELECT bad",
                "config": {},
                "width": "full"
            }]
        }
        results = {
            "error_comp": {
                "status": "error",
                "error": "Column 'bad' not found",
                "row_count": 0
            }
        }
        validation = validate_and_explain(app_def, results)
        assert validation["overall_status"] != "success"
