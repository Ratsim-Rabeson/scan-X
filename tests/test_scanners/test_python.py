"""Tests for the PythonScanner."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 – used at runtime

import pytest

from scan_x.scanners.python_scanner import PythonScanner


@pytest.fixture
def scanner() -> PythonScanner:
    return PythonScanner()


# -- can_scan ----------------------------------------------------------------


class TestCanScan:
    def test_with_requirements_txt(self, scanner: PythonScanner, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==3.0.0")
        assert scanner.can_scan(tmp_path) is True

    def test_with_poetry_lock(self, scanner: PythonScanner, tmp_path: Path) -> None:
        (tmp_path / "poetry.lock").write_text("")
        assert scanner.can_scan(tmp_path) is True

    def test_with_pipfile_lock(self, scanner: PythonScanner, tmp_path: Path) -> None:
        (tmp_path / "Pipfile.lock").write_text("{}")
        assert scanner.can_scan(tmp_path) is True

    def test_with_pyproject_poetry(self, scanner: PythonScanner, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[tool.poetry]\nname = 'test'\n")
        assert scanner.can_scan(tmp_path) is True

    def test_with_pyproject_project(self, scanner: PythonScanner, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
        assert scanner.can_scan(tmp_path) is True

    def test_empty_dir_false(self, scanner: PythonScanner, tmp_path: Path) -> None:
        assert scanner.can_scan(tmp_path) is False

    def test_pyproject_without_markers_false(self, scanner: PythonScanner, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 80\n")
        assert scanner.can_scan(tmp_path) is False


# -- parse_dependencies: requirements.txt ------------------------------------


class TestParseRequirementsTxt:
    async def test_pinned_versions(self, scanner: PythonScanner, tmp_path: Path) -> None:
        content = """\
flask==3.0.0
requests==2.31.0
numpy>=1.26.0
"""
        (tmp_path / "requirements.txt").write_text(content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 3

        flask = next(d for d in deps if d.name == "flask")
        assert flask.version == "3.0.0"
        assert flask.ecosystem == "PyPI"

    async def test_comments_and_blanks_skipped(
        self, scanner: PythonScanner, tmp_path: Path
    ) -> None:
        content = """\
# This is a comment

flask==3.0.0

# Another comment
requests==2.31.0
"""
        (tmp_path / "requirements.txt").write_text(content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 2

    async def test_options_ignored(self, scanner: PythonScanner, tmp_path: Path) -> None:
        content = """\
--index-url https://pypi.org/simple
flask==3.0.0
"""
        (tmp_path / "requirements.txt").write_text(content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "flask"

    async def test_bare_package_name(self, scanner: PythonScanner, tmp_path: Path) -> None:
        content = "flask\n"
        (tmp_path / "requirements.txt").write_text(content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "flask"
        assert deps[0].version == "*"

    async def test_environment_markers_stripped(
        self, scanner: PythonScanner, tmp_path: Path
    ) -> None:
        content = 'pywin32==306 ; sys_platform == "win32"\n'
        (tmp_path / "requirements.txt").write_text(content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "pywin32"

    async def test_recursive_includes(self, scanner: PythonScanner, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("-r base.txt\nflask==3.0.0\n")
        (tmp_path / "base.txt").write_text("requests==2.31.0\n")

        deps = await scanner.parse_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "flask" in names
        assert "requests" in names


# -- parse_dependencies: poetry.lock -----------------------------------------


class TestParsePoetryLock:
    async def test_toml_format(self, scanner: PythonScanner, tmp_path: Path) -> None:
        content = """\
[[package]]
name = "flask"
version = "3.0.0"
description = "A micro web framework"

[[package]]
name = "click"
version = "8.1.7"
description = "Composable command line interface toolkit"
"""
        (tmp_path / "poetry.lock").write_text(content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"flask", "click"}

        flask = next(d for d in deps if d.name == "flask")
        assert flask.version == "3.0.0"
        assert flask.ecosystem == "PyPI"


# -- parse_dependencies: Pipfile.lock ----------------------------------------


class TestParsePipfileLock:
    async def test_default_and_develop(self, scanner: PythonScanner, tmp_path: Path) -> None:
        content = {
            "_meta": {},
            "default": {
                "flask": {"version": "==3.0.0"},
                "requests": {"version": "==2.31.0"},
            },
            "develop": {
                "pytest": {"version": "==8.0.0"},
            },
        }
        import json

        (tmp_path / "Pipfile.lock").write_text(json.dumps(content))

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 3

        pytest_dep = next(d for d in deps if d.name == "pytest")
        assert pytest_dep.dev is True
        assert pytest_dep.version == "8.0.0"
