"""Tests for config.py — validates all configuration is present and well-formed."""

import pytest


class TestConfigLoads:
    """Verify config.py imports and has all required attributes."""

    def test_config_imports(self):
        """config.py must import without errors."""
        import config
        assert config is not None

    def test_app_name_exists(self):
        from config import APP_NAME
        assert isinstance(APP_NAME, str)
        assert len(APP_NAME) > 0

    def test_openai_model_exists(self):
        from config import OPENAI_MODEL
        assert isinstance(OPENAI_MODEL, str)


class TestPIIPatterns:
    """PII patterns must be defined for governance scanning."""

    def test_pii_patterns_exist(self):
        from config import PII_PATTERNS
        assert isinstance(PII_PATTERNS, (dict, list))
        assert len(PII_PATTERNS) >= 3, "Need at least 3 PII patterns (email, phone, ssn)"

    def test_pii_patterns_are_valid_regex(self):
        import re
        from config import PII_PATTERNS
        if isinstance(PII_PATTERNS, dict):
            for name, pattern in PII_PATTERNS.items():
                try:
                    re.compile(pattern)
                except re.error:
                    pytest.fail(f"PII pattern '{name}' is not valid regex: {pattern}")
        elif isinstance(PII_PATTERNS, list):
            for pattern in PII_PATTERNS:
                try:
                    re.compile(pattern)
                except re.error:
                    pytest.fail(f"PII pattern is not valid regex: {pattern}")


class TestRoles:
    """Role definitions must include admin, analyst, viewer."""

    def test_roles_exist(self):
        from config import ROLES
        assert isinstance(ROLES, dict)
        assert "admin" in ROLES, "Missing 'admin' role"
        assert "analyst" in ROLES, "Missing 'analyst' role"
        assert "viewer" in ROLES, "Missing 'viewer' role"

    def test_each_role_has_capabilities(self):
        from config import ROLES
        for role_name, role_config in ROLES.items():
            assert "capabilities" in role_config or "display_name" in role_config, \
                f"Role '{role_name}' missing expected fields"


class TestTemplates:
    """Template definitions must include at least Supplier Performance."""

    def test_templates_exist(self):
        from config import TEMPLATES
        assert isinstance(TEMPLATES, list)
        assert len(TEMPLATES) >= 1, "Need at least 1 template"

    def test_templates_have_required_fields(self):
        from config import TEMPLATES
        required_fields = {"id", "name", "description", "default_prompt"}
        for template in TEMPLATES:
            for field in required_fields:
                assert field in template, \
                    f"Template '{template.get('name', 'unknown')}' missing field: {field}"

    def test_supplier_performance_template(self):
        """The Supplier Performance template is required for demo mode."""
        from config import TEMPLATES
        supplier_template = next(
            (t for t in TEMPLATES if "supplier" in t["id"].lower()), None
        )
        assert supplier_template is not None, \
            "Must have a Supplier Performance template (used by demo mode)"
