"""tests/test_docker.py — validation tests for official Dockerfile and docker-compose.yml."""
from __future__ import annotations

from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_dockerignore_exists_and_excludes_sensitive():
    dockerignore_path = REPO_ROOT / ".dockerignore"
    assert dockerignore_path.exists(), ".dockerignore file must exist"
    content = dockerignore_path.read_text(encoding="utf-8")
    lines = {line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")}

    assert ".git" in lines
    assert "__pycache__" in lines
    assert ".pytest_cache" in lines
    assert "venv" in lines or ".venv" in lines
    assert "tests" in lines


def test_dockerfile_structure():
    dockerfile_path = REPO_ROOT / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist"
    content = dockerfile_path.read_text(encoding="utf-8")

    # Multi-stage build checks
    assert "AS builder" in content, "Dockerfile should use multi-stage build (builder stage)"
    assert "AS runner" in content, "Dockerfile should have a runner stage"

    # Security: non-root user
    assert "10001" in content, "Dockerfile must configure non-root user/group 10001"
    assert "USER 10001:10001" in content, "Dockerfile must run as unprivileged user"

    # Healthcheck
    assert "HEALTHCHECK" in content, "Dockerfile must define a HEALTHCHECK"

    # Entrypoint
    assert 'ENTRYPOINT ["prismor"]' in content, "Dockerfile entrypoint should be 'prismor'"


def test_docker_compose_validity():
    compose_path = REPO_ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))

    assert "services" in data, "docker-compose.yml must define services"
    services = data["services"]

    # Dashboard service check
    assert "dashboard" in services, "docker-compose.yml must define a 'dashboard' service"
    dashboard = services["dashboard"]
    assert dashboard.get("read_only") is True, "dashboard service should specify read_only: true"
    assert "ALL" in dashboard.get("cap_drop", []), "dashboard service should drop all capabilities"
    assert "no-new-privileges:true" in dashboard.get("security_opt", []), "dashboard should enforce no-new-privileges"
    assert "healthcheck" in dashboard, "dashboard should have healthcheck defined"

    # Volumes check
    assert "volumes" in data, "docker-compose.yml must define named volumes"
    assert "prismor_data" in data["volumes"], "prismor_data volume must be defined"
