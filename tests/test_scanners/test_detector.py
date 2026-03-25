"""Tests for the ProjectDetector."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 – used at runtime

import pytest

from scan_x.models.project import ProjectType
from scan_x.scanners.detector import ProjectDetector


@pytest.fixture
def detector() -> ProjectDetector:
    return ProjectDetector()


class TestDetectNodeJS:
    def test_package_lock(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text("{}")
        detected = detector.detect(tmp_path)
        assert ProjectType.NODEJS in detected

    def test_yarn_lock(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "yarn.lock").write_text("")
        detected = detector.detect(tmp_path)
        assert ProjectType.NODEJS in detected

    def test_package_json(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("{}")
        detected = detector.detect(tmp_path)
        assert ProjectType.NODEJS in detected


class TestDetectPython:
    def test_requirements_txt(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0")
        detected = detector.detect(tmp_path)
        assert ProjectType.PYTHON in detected

    def test_poetry_lock(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "poetry.lock").write_text("")
        detected = detector.detect(tmp_path)
        assert ProjectType.PYTHON in detected

    def test_pipfile_lock(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "Pipfile.lock").write_text("{}")
        detected = detector.detect(tmp_path)
        assert ProjectType.PYTHON in detected

    def test_pyproject_toml_with_project(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'foo'\n")
        detected = detector.detect(tmp_path)
        assert ProjectType.PYTHON in detected

    def test_pyproject_toml_without_python_markers(
        self, detector: ProjectDetector, tmp_path: Path
    ) -> None:
        (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 80\n")
        detected = detector.detect(tmp_path)
        assert ProjectType.PYTHON not in detected


class TestDetectMaven:
    def test_pom_xml(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "pom.xml").write_text("<project></project>")
        detected = detector.detect(tmp_path)
        assert ProjectType.MAVEN in detected


class TestDetectGradle:
    def test_build_gradle(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "build.gradle").write_text("")
        detected = detector.detect(tmp_path)
        assert ProjectType.GRADLE in detected

    def test_build_gradle_kts(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "build.gradle.kts").write_text("")
        detected = detector.detect(tmp_path)
        assert ProjectType.GRADLE in detected


class TestDetectDotNet:
    def test_packages_config(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "packages.config").write_text("")
        detected = detector.detect(tmp_path)
        assert ProjectType.DOTNET in detected

    def test_csproj_glob(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "MyApp.csproj").write_text("")
        detected = detector.detect(tmp_path)
        assert ProjectType.DOTNET in detected


class TestMultiProjectRepos:
    def test_multiple_types_detected(self, detector: ProjectDetector, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("flask==3.0")
        (tmp_path / "pom.xml").write_text("<project/>")

        detected = detector.detect(tmp_path)
        assert ProjectType.NODEJS in detected
        assert ProjectType.PYTHON in detected
        assert ProjectType.MAVEN in detected
        assert len(detected) == 3

    def test_empty_directory(self, detector: ProjectDetector, tmp_path: Path) -> None:
        detected = detector.detect(tmp_path)
        assert detected == []
