"""Unit tests for configuration models."""

import pytest
from pydantic import ValidationError

from bbai.core.config_models import (
    BBAIConfig,
    ProgramConfig,
    RateLimitConfig,
    ScopeRule,
    Severity,
    ThoughtType,
    TimingConfig,
)


class TestScopeRule:
    """Test ScopeRule model."""

    def test_valid_wildcard_pattern(self):
        rule = ScopeRule(pattern="*.example.com")
        assert rule.pattern == "*.example.com"
        assert not rule.is_regex

    def test_valid_regex_pattern(self):
        rule = ScopeRule(pattern=r".*\.example\.com", is_regex=True)
        assert rule.is_regex

    def test_empty_pattern_raises(self):
        with pytest.raises(ValidationError):
            ScopeRule(pattern="")

    def test_wildcard_matching(self):
        rule = ScopeRule(pattern="*.example.com")
        assert rule.matches("sub.example.com")
        assert rule.matches("example.com")
        assert not rule.matches("other.com")

    def test_exact_matching(self):
        rule = ScopeRule(pattern="example.com")
        assert rule.matches("example.com")
        assert not rule.matches("sub.example.com")

    def test_regex_matching(self):
        rule = ScopeRule(pattern=r"test\d+\.example\.com", is_regex=True)
        assert rule.matches("test123.example.com")
        assert not rule.matches("test.example.com")

    def test_case_insensitive_matching(self):
        rule = ScopeRule(pattern="EXAMPLE.COM")
        assert rule.matches("example.com")
        assert rule.matches("EXAMPLE.COM")


class TestTimingConfig:
    """Test TimingConfig model."""

    def test_default_values(self):
        config = TimingConfig()
        assert config.timezone == "UTC"
        assert config.blocked_hours is None
        assert config.max_requests_per_second == 5.0

    def test_valid_blocked_hours(self):
        config = TimingConfig(blocked_hours="09:00-17:00")
        assert config.blocked_hours == "09:00-17:00"

    def test_invalid_blocked_hours_format(self):
        with pytest.raises(ValidationError):
            TimingConfig(blocked_hours="invalid")

    def test_invalid_time_range(self):
        with pytest.raises(ValidationError):
            TimingConfig(blocked_hours="25:00-17:00")

    def test_rate_limits(self):
        with pytest.raises(ValidationError):
            TimingConfig(max_requests_per_second=0.0)
        with pytest.raises(ValidationError):
            TimingConfig(max_requests_per_second=101.0)


class TestProgramConfig:
    """Test ProgramConfig model."""

    def test_minimum_required(self):
        config = ProgramConfig(name="test-program")
        assert config.name == "test-program"
        assert config.platform == "custom"

    def test_scope_conflict_detection(self):
        with pytest.raises(ValidationError):
            ProgramConfig(
                name="test",
                scope_in=[ScopeRule(pattern="example.com")],
                scope_out=[ScopeRule(pattern="example.com")],
            )

    def test_computed_fields(self):
        config = ProgramConfig(name="test")
        assert not config.has_restricted_timing
        assert not config.is_fully_open_scope

        config_with_timing = ProgramConfig(
            name="test",
            timing=TimingConfig(blocked_hours="09:00-17:00"),
        )
        assert config_with_timing.has_restricted_timing

        open_scope_config = ProgramConfig(
            name="test",
            scope_in=[ScopeRule(pattern="*")],
        )
        assert open_scope_config.is_fully_open_scope


class TestBBAIConfig:
    """Test BBAIConfig model."""

    def test_default_values(self):
        config = BBAIConfig()
        assert config.moonshot_model == "kimi-k2-5"
        assert config.theme == "dark"
        assert config.show_thought_stream is True

    def test_directories_created(self, tmp_path):
        config = BBAIConfig(data_dir=tmp_path / ".bbai")
        # Directories are created by model_validator, verify they exist
        assert config.data_dir.exists()
        assert config.projects_dir.exists()
        assert config.logs_dir.exists()


class TestEnums:
    """Test enum definitions."""

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_thought_type_values(self):
        assert ThoughtType.ANALYZING.value == "analyzing"
        assert ThoughtType.DECIDING.value == "deciding"
        assert ThoughtType.WARNING.value == "warning"
        assert ThoughtType.ERROR.value == "error"
        assert ThoughtType.SUCCESS.value == "success"
