"""Unit tests for Docker client."""

import pytest

from bbai.tools.docker_client import ContainerConfig, DockerImageManager, ToolResult


class TestContainerConfig:
    """Test ContainerConfig dataclass."""

    def test_default_values(self):
        config = ContainerConfig(image="test:latest", command=["echo", "hello"])
        
        assert config.image == "test:latest"
        assert config.command == ["echo", "hello"]
        assert config.mem_limit == "512m"
        assert config.cpu_quota == 50000
        assert config.read_only is True
        assert config.user == "1000:1000"
        assert config.working_dir == "/workspace"

    def test_custom_values(self):
        config = ContainerConfig(
            image="test:latest",
            command="echo hello",
            mem_limit="1g",
            cpu_quota=100000,
            read_only=False,
            user="root",
        )
        
        assert config.mem_limit == "1g"
        assert config.cpu_quota == 100000
        assert config.read_only is False
        assert config.user == "root"

    def test_security_defaults(self):
        config = ContainerConfig(image="test:latest", command=["echo"])
        
        assert config.security_opt == ["no-new-privileges:true"]
        assert config.cap_drop == ["ALL"]
        assert config.cap_add == ["NET_RAW"]


class TestToolResult:
    """Test ToolResult dataclass."""

    def test_success_result(self):
        result = ToolResult(
            success=True,
            exit_code=0,
            stdout="output",
            stderr="",
            execution_time=5.0,
            container_id="abc123",
        )
        
        assert result.success is True
        assert result.exit_code == 0
        assert result.container_id == "abc123"

    def test_failure_result(self):
        result = ToolResult(
            success=False,
            exit_code=1,
            stdout="",
            stderr="error",
            execution_time=1.0,
            error_message="Command failed",
        )
        
        assert result.success is False
        assert result.error_message == "Command failed"

    def test_to_tool_output(self):
        result = ToolResult(
            success=True,
            exit_code=0,
            stdout="vuln found",
            stderr="",
            execution_time=5.0,
        )
        
        output = result.to_tool_output("nuclei")
        
        assert output.tool_name == "nuclei"
        assert output.exit_code == 0
        assert output.stdout == "vuln found"
        assert output.execution_time == 5.0


class TestDockerImageManager:
    """Test DockerImageManager."""

    @pytest.fixture
    def manager(self):
        return DockerImageManager()

    def test_images_defined(self, manager):
        """Test that all 8 images are defined."""
        assert len(manager.IMAGES) == 8
        
        expected = [
            "bbai-recon-passive",
            "bbai-recon-active",
            "bbai-content-discovery",
            "bbai-vulnerability-core",
            "bbai-secrets",
            "bbai-js-analysis",
            "bbai-cloud",
            "bbai-visual",
        ]
        
        for img in expected:
            assert img in manager.IMAGES

    def test_image_metadata(self, manager):
        """Test that images have metadata."""
        for name, meta in manager.IMAGES.items():
            assert "tools" in meta
            assert "size" in meta
            assert len(meta["tools"]) > 0

    def test_get_missing_images(self, manager):
        """Test getting missing images list."""
        status = {
            "bbai-recon-passive": True,
            "bbai-secrets": False,
        }
        
        missing = manager.get_missing_images(status)
        assert "bbai-secrets" in missing
        assert "bbai-recon-passive" not in missing
