"""Tests for config.py — validates all configuration is present and well-formed."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_config_imports():
    """config.py must import without errors."""
    print("Testing config imports...")
    try:
        import config
        assert config is not None
        print("✅ Config imports test passed")
    except Exception as e:
        print(f"❌ Config imports test failed: {e}")
        raise


def test_app_name_exists():
    """APP_NAME must exist and be a non-empty string."""
    print("Testing APP_NAME...")
    try:
        from config import APP_NAME
        assert isinstance(APP_NAME, str), "APP_NAME must be a string"
        assert len(APP_NAME) > 0, "APP_NAME must not be empty"
        print("✅ APP_NAME test passed")
    except Exception as e:
        print(f"❌ APP_NAME test failed: {e}")
        raise


def test_openai_model_exists():
    """OPENAI_MODEL must exist and be a string."""
    print("Testing OPENAI_MODEL...")
    try:
        from config import OPENAI_MODEL
        assert isinstance(OPENAI_MODEL, str), "OPENAI_MODEL must be a string"
        print("✅ OPENAI_MODEL test passed")
    except Exception as e:
        print(f"❌ OPENAI_MODEL test failed: {e}")
        raise


def test_pii_patterns_exist():
    """PII_PATTERNS must be defined with at least 3 patterns."""
    print("Testing PII patterns existence...")
    try:
        from config import PII_PATTERNS
        assert isinstance(PII_PATTERNS, (dict, list)), "PII_PATTERNS must be dict or list"
        assert len(PII_PATTERNS) >= 3, "Need at least 3 PII patterns (email, phone, ssn)"
        print("✅ PII patterns existence test passed")
    except Exception as e:
        print(f"❌ PII patterns existence test failed: {e}")
        raise


def test_pii_patterns_are_valid_regex():
    """PII patterns must be valid regular expressions."""
    print("Testing PII patterns regex validity...")
    try:
        import re
        from config import PII_PATTERNS

        if isinstance(PII_PATTERNS, dict):
            for name, pattern in PII_PATTERNS.items():
                try:
                    re.compile(pattern)
                except re.error as e:
                    raise AssertionError(f"PII pattern '{name}' is not valid regex: {pattern} - {e}")
        elif isinstance(PII_PATTERNS, list):
            for i, pattern in enumerate(PII_PATTERNS):
                try:
                    re.compile(pattern)
                except re.error as e:
                    raise AssertionError(f"PII pattern at index {i} is not valid regex: {pattern} - {e}")

        print("✅ PII patterns regex test passed")
    except Exception as e:
        print(f"❌ PII patterns regex test failed: {e}")
        raise


def test_roles_exist():
    """ROLES must include admin, analyst, viewer."""
    print("Testing roles existence...")
    try:
        from config import ROLES
        assert isinstance(ROLES, dict), "ROLES must be a dict"
        assert "admin" in ROLES, "Missing 'admin' role"
        assert "analyst" in ROLES, "Missing 'analyst' role"
        assert "viewer" in ROLES, "Missing 'viewer' role"
        print("✅ Roles existence test passed")
    except Exception as e:
        print(f"❌ Roles existence test failed: {e}")
        raise


def test_each_role_has_capabilities():
    """Each role must have capabilities or display_name."""
    print("Testing role capabilities...")
    try:
        from config import ROLES
        for role_name, role_config in ROLES.items():
            assert "capabilities" in role_config or "display_name" in role_config, \
                f"Role '{role_name}' missing expected fields"
        print("✅ Role capabilities test passed")
    except Exception as e:
        print(f"❌ Role capabilities test failed: {e}")
        raise


def test_templates_exist():
    """TEMPLATES must include at least 1 template."""
    print("Testing templates existence...")
    try:
        from config import TEMPLATES
        assert isinstance(TEMPLATES, list), "TEMPLATES must be a list"
        assert len(TEMPLATES) >= 1, "Need at least 1 template"
        print("✅ Templates existence test passed")
    except Exception as e:
        print(f"❌ Templates existence test failed: {e}")
        raise


def test_templates_have_required_fields():
    """Templates must have required fields."""
    print("Testing template required fields...")
    try:
        from config import TEMPLATES
        required_fields = {"id", "name", "description", "default_prompt"}
        for template in TEMPLATES:
            for field in required_fields:
                assert field in template, \
                    f"Template '{template.get('name', 'unknown')}' missing field: {field}"
        print("✅ Template required fields test passed")
    except Exception as e:
        print(f"❌ Template required fields test failed: {e}")
        raise


def test_supplier_performance_template():
    """The Supplier Performance template is required for demo mode."""
    print("Testing supplier performance template...")
    try:
        from config import TEMPLATES
        supplier_template = next(
            (t for t in TEMPLATES if "supplier" in t["id"].lower()), None
        )
        assert supplier_template is not None, \
            "Must have a Supplier Performance template (used by demo mode)"
        print("✅ Supplier performance template test passed")
    except Exception as e:
        print(f"❌ Supplier performance template test failed: {e}")
        raise


def run_all_config_tests():
    """Run all config tests."""
    print("🧪 Running Config Tests")
    print("=" * 40)

    tests = [
        test_config_imports,
        test_app_name_exists,
        test_openai_model_exists,
        test_pii_patterns_exist,
        test_pii_patterns_are_valid_regex,
        test_roles_exist,
        test_each_role_has_capabilities,
        test_templates_exist,
        test_templates_have_required_fields,
        test_supplier_performance_template,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            failed += 1
        print()

    print("=" * 40)
    print(f"📊 Config Test Results: {passed} passed, {failed} failed")

    if failed > 0:
        print("❌ Some config tests failed!")
        return False
    else:
        print("🎉 All config tests passed!")
        return True


if __name__ == "__main__":
    success = run_all_config_tests()
    sys.exit(0 if success else 1)
