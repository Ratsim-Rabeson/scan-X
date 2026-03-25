"""Tests for the NpmScanner."""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003 – used at runtime

import pytest

from scan_x.scanners.npm import NpmScanner


@pytest.fixture
def scanner() -> NpmScanner:
    return NpmScanner()


# -- can_scan ----------------------------------------------------------------


class TestCanScan:
    def test_with_package_lock(self, scanner: NpmScanner, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text("{}")
        assert scanner.can_scan(tmp_path) is True

    def test_with_yarn_lock(self, scanner: NpmScanner, tmp_path: Path) -> None:
        (tmp_path / "yarn.lock").write_text("")
        assert scanner.can_scan(tmp_path) is True

    def test_with_package_json(self, scanner: NpmScanner, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("{}")
        assert scanner.can_scan(tmp_path) is True

    def test_empty_dir_false(self, scanner: NpmScanner, tmp_path: Path) -> None:
        assert scanner.can_scan(tmp_path) is False


# -- parse_dependencies: package-lock.json -----------------------------------


class TestParsePackageLock:
    async def test_npm_v7_packages_key(self, scanner: NpmScanner, tmp_path: Path) -> None:
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/lodash": {"version": "4.17.21", "dev": True},
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 2

        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names

        lodash = next(d for d in deps if d.name == "lodash")
        assert lodash.dev is True
        assert lodash.ecosystem == "npm"

    async def test_npm_v5_dependencies_fallback(
        self, scanner: NpmScanner, tmp_path: Path
    ) -> None:
        lock_data = {
            "lockfileVersion": 1,
            "dependencies": {
                "react": {"version": "18.2.0"},
                "react-dom": {"version": "18.2.0"},
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"react", "react-dom"}

    async def test_skips_empty_version(self, scanner: NpmScanner, tmp_path: Path) -> None:
        lock_data = {
            "packages": {
                "": {},
                "node_modules/bad": {"version": ""},
                "node_modules/good": {"version": "1.0.0"},
            }
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "good"


# -- parse_dependencies: yarn.lock -------------------------------------------


class TestParseYarnLock:
    async def test_yarn_v1_format(self, scanner: NpmScanner, tmp_path: Path) -> None:
        yarn_content = """\
# yarn lockfile v1

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"""
        (tmp_path / "yarn.lock").write_text(yarn_content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"express", "lodash"}

    async def test_scoped_package(self, scanner: NpmScanner, tmp_path: Path) -> None:
        yarn_content = """\
"@babel/core@^7.0.0":
  version "7.23.0"
"""
        (tmp_path / "yarn.lock").write_text(yarn_content)

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "@babel/core"
        assert deps[0].version == "7.23.0"


# -- parse_dependencies: package.json fallback --------------------------------


class TestParsePackageJson:
    async def test_deps_and_dev_deps(self, scanner: NpmScanner, tmp_path: Path) -> None:
        pkg = {
            "dependencies": {"axios": "^1.6.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))

        deps = await scanner.parse_dependencies(tmp_path)
        assert len(deps) == 2

        axios = next(d for d in deps if d.name == "axios")
        assert axios.dev is False

        jest = next(d for d in deps if d.name == "jest")
        assert jest.dev is True
