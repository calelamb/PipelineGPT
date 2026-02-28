"""
Integration tests — validates the full engine pipeline end to end.

Tests the contract: user prompt → app_definition → execution → validation → governance.

The mock pipeline test runs WITHOUT an API key.
The live pipeline test runs ONLY if OPENAI_API_KEY is set.
"""

import os
import json
import pytest
import pandas as pd


class TestMockPipeline:
    """Full pipeline using mock app_definition (no API key needed)."""

    def test_execute_then_validate(self, db_conn, mock_app_definition):
        """Execute mock app definition against real DuckDB, then validate."""
        from engine.executor import execute_app_components
        from engine.validator import validate_and_explain

        # Step 1: Execute all component queries
        results = execute_app_components(db_conn, mock_app_definition)
        assert len(results) > 0, "Execution returned no results"

        # Step 2: Validate the results
        validation = validate_and_explain(mock_app_definition, results)
        assert validation["overall_status"] in ["success", "warning", "error"]

        # At least half the components should succeed
        success_count = sum(
            1 for r in results.values()
            if r.get("status") == "success"
        )
        total = len(results)
        assert success_count >= total // 2, \
            f"Only {success_count}/{total} components succeeded"

    def test_execute_validate_govern(self, db_conn, mock_app_definition):
        """Full pipeline: execute → validate → governance."""
        from engine.executor import execute_app_components
        from engine.validator import validate_and_explain
        from engine.governance import run_governance_checks

        results = execute_app_components(db_conn, mock_app_definition)
        validation = validate_and_explain(mock_app_definition, results)
        governance = run_governance_checks(mock_app_definition, "analyst")

        # All three stages must return dicts
        assert isinstance(results, dict)
        assert isinstance(validation, dict)
        assert isinstance(governance, dict)

        # Governance must have checks
        assert len(governance.get("checks", [])) >= 1

    def test_app_definition_contract_shape(self, mock_app_definition):
        """The mock app_definition must match the exact contract schema.

        This is THE critical test — if this shape doesn't match,
        Person 2's UI will break on integration day.
        """
        app = mock_app_definition

        # Top-level required fields
        assert "app_title" in app
        assert "components" in app
        assert isinstance(app["components"], list)
        assert len(app["components"]) >= 1

        # Each component must have required fields
        for comp in app["components"]:
            assert "id" in comp, f"Component missing 'id': {comp}"
            assert "type" in comp, f"Component missing 'type': {comp}"
            assert "title" in comp, f"Component missing 'title': {comp}"
            assert "sql_query" in comp, f"Component missing 'sql_query': {comp}"
            assert "width" in comp, f"Component missing 'width': {comp}"

            # Type must be one of the allowed types
            allowed_types = [
                "kpi_card", "bar_chart", "line_chart", "pie_chart",
                "scatter_plot", "table", "metric_highlight", "area_chart"
            ]
            assert comp["type"] in allowed_types, \
                f"Invalid component type: {comp['type']}"

            # Width must be valid
            allowed_widths = ["full", "half", "third"]
            assert comp["width"] in allowed_widths, \
                f"Invalid width: {comp['width']}"

        # Filters (optional but expected)
        if "filters" in app:
            for f in app["filters"]:
                assert "column" in f, f"Filter missing 'column': {f}"
                assert "type" in f or "filter_type" in f, f"Filter missing type: {f}"

    def test_execution_results_contract_shape(self, db_conn, mock_app_definition):
        """Execution results must match the shape Person 2's UI expects."""
        from engine.executor import execute_app_components
        results = execute_app_components(db_conn, mock_app_definition)

        for comp_id, result in results.items():
            assert "status" in result, f"Result '{comp_id}' missing 'status'"
            assert result["status"] in ["success", "error"], \
                f"Invalid status: {result['status']}"

            if result["status"] == "success":
                assert "data" in result, f"Success result '{comp_id}' missing 'data'"
                assert isinstance(result["data"], pd.DataFrame), \
                    f"Result '{comp_id}' data is not a DataFrame"


@pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set — skipping live API test"
)
class TestLivePipeline:
    """Full pipeline with REAL OpenAI API call. Only runs if API key is set."""

    def test_live_intent_parsing(self, db_conn):
        """Real GPT-5.1 call → execute → validate → governance."""
        from data.sample_data_loader import get_table_schema, get_sample_rows
        from engine.intent_parser import parse_intent
        from engine.executor import execute_app_components
        from engine.validator import validate_and_explain
        from engine.governance import run_governance_checks

        # Step 1: Parse intent with real API
        schema = get_table_schema(db_conn)
        samples = get_sample_rows(db_conn)
        schema_ctx = schema + "\n\nSample rows:\n" + samples.to_string(index=False)

        app_def = parse_intent(
            "Show me supplier defect rates by region",
            table_schema=schema_ctx
        )

        # Validate the shape
        assert "app_title" in app_def or "title" in app_def
        assert "components" in app_def
        assert len(app_def["components"]) >= 1

        # Step 2: Execute
        results = execute_app_components(db_conn, app_def)
        success_count = sum(1 for r in results.values() if r.get("status") == "success")
        assert success_count >= 1, "At least 1 component should execute successfully"

        # Step 3: Validate
        validation = validate_and_explain(app_def, results)
        assert validation is not None

        # Step 4: Governance
        governance = run_governance_checks(app_def, "analyst")
        assert governance is not None

        print(f"\n✅ LIVE PIPELINE TEST PASSED")
        print(f"   App: {app_def.get('app_title', 'N/A')}")
        print(f"   Components: {len(app_def['components'])}")
        print(f"   Executed: {success_count}/{len(results)}")
        print(f"   Governance: {governance.get('overall_status', 'N/A')}")

    def test_live_refinement(self, db_conn):
        """Test conversational refinement — modify existing app via follow-up."""
        from data.sample_data_loader import get_table_schema, get_sample_rows
        from engine.intent_parser import parse_intent

        schema = get_table_schema(db_conn)
        samples = get_sample_rows(db_conn)
        schema_ctx = schema + "\n\nSample rows:\n" + samples.to_string(index=False)

        # Build initial app
        app_v1 = parse_intent(
            "Show supplier defect rates",
            table_schema=schema_ctx
        )
        v1_count = len(app_v1.get("components", []))

        # Refine it
        app_v2 = parse_intent(
            "Add a breakdown by shipping mode",
            existing_app=app_v1,
            table_schema=schema_ctx
        )
        v2_count = len(app_v2.get("components", []))

        # Refined app should exist and ideally have more or different components
        assert app_v2 is not None
        assert v2_count >= 1
        print(f"\n✅ REFINEMENT TEST PASSED: v1={v1_count} components → v2={v2_count} components")


class TestDynamicSchemaInjection:
    """Schema and sample rows must be injected dynamically, not hardcoded."""

    def test_schema_contains_actual_columns(self, db_conn):
        from data.sample_data_loader import get_table_schema
        schema = get_table_schema(db_conn)
        assert "supplier" in schema.lower()
        assert "defect_rate" in schema.lower()
        assert "region" in schema.lower()

    def test_sample_rows_reflect_actual_data(self, db_conn):
        from data.sample_data_loader import get_sample_rows
        samples = get_sample_rows(db_conn)
        assert "supplier" in [c.lower() for c in samples.columns]
        assert len(samples) >= 3
        # Verify the sample values are actual data, not placeholders
        assert samples.iloc[0, 0] is not None
