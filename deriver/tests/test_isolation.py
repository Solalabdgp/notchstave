"""The deriver's dependency isolation, enforced instead of documented.

TZ 4 and 5.8/T4: the deriver is the only process that holds key material, and
it must not be able to reach the network or to import the rest of the system.
``deriver/pyproject.toml`` states that in prose and in a dependency list; this
file turns it into a build failure.

Static analysis over the AST rather than importing the modules, on purpose. An
import-based check would only observe what happens to be imported at runtime,
and would itself pull the network libraries into the process it is trying to
prove clean. Parsing the source sees every import, including ones inside
functions and inside ``TYPE_CHECKING`` blocks.

What this catches in practice: someone adds `import httpx` to fetch the chain
head "just for reserved_from_block", and the process holding the xpub gains an
outbound socket. That is not a hypothetical — needing the block height at
reservation time (TZ 5.1 p. 2, condition 3) creates exactly that temptation.
The height is passed in as an argument for this reason.
"""

from __future__ import annotations

import ast
from pathlib import Path

try:  # Python 3.11+ — the version this project targets.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - only on an older local interpreter
    import tomli as tomllib  # type: ignore[no-redef]

import pytest

DERIVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = DERIVER_DIR.parent

#: Anything that can open a socket, directly or as a client library.
FORBIDDEN_NETWORK_MODULES = frozenset(
    {
        "requests",
        "httpx",
        "aiohttp",
        "urllib",
        "urllib3",
        "http",
        "socket",
        "socketserver",
        "ssl",
        "ftplib",
        "telnetlib",
        "smtplib",
        "asyncio",
        "web3",
        "eth_account",
        "redis",
        "celery",
        "kombu",
        "aiogram",
        "fastapi",
        "uvicorn",
        "starlette",
        "telegram",
        "websockets",
        "grpc",
        "paramiko",
        "boto3",
    }
)

#: The sibling processes. The deriver emits addresses outward and imports
#: nothing back — that one-way boundary is item 4 of the trust boundaries in
#: TZ 5.8 ("наружу уходят только адреса и индексы").
FORBIDDEN_PROJECT_PACKAGES = frozenset(
    {"core", "api", "bot", "watcher", "settler", "notifier", "migrations"}
)

#: Verbatim from deriver/pyproject.toml's own stated invariant.
ALLOWED_DEPENDENCIES = frozenset({"bip-utils", "coincurve", "pydantic", "psycopg"})


def deriver_source_files() -> list[Path]:
    return sorted(p for p in DERIVER_DIR.rglob("*.py") if "__pycache__" not in p.parts)


def imported_root_modules(path: Path) -> set[str]:
    """Every top-level module name imported by this file, at any nesting depth."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import, stays inside the package
                continue
            if node.module:
                roots.add(node.module.split(".")[0])
    return roots


def production_source_files() -> list[Path]:
    """Package modules only — the tests themselves may import test helpers."""
    return [p for p in deriver_source_files() if "tests" not in p.parts]


def test_there_is_something_to_check() -> None:
    """Guards against the whole suite passing because the glob found nothing."""
    files = production_source_files()

    assert len(files) >= 4
    assert {p.name for p in files} >= {"derivation.py", "service.py", "pool.py", "redaction.py"}


@pytest.mark.parametrize("path", production_source_files(), ids=lambda p: p.name)
def test_no_network_capable_imports(path: Path) -> None:
    """The process holding the xpub cannot open a socket."""
    offending = imported_root_modules(path) & FORBIDDEN_NETWORK_MODULES

    assert not offending, f"{path.name} imports network-capable module(s): {sorted(offending)}"


@pytest.mark.parametrize("path", production_source_files(), ids=lambda p: p.name)
def test_no_imports_from_sibling_processes(path: Path) -> None:
    """One-way boundary: nothing flows back into the deriver (TZ 5.8)."""
    offending = imported_root_modules(path) & FORBIDDEN_PROJECT_PACKAGES

    assert not offending, f"{path.name} imports sibling package(s): {sorted(offending)}"


@pytest.mark.parametrize("path", production_source_files(), ids=lambda p: p.name)
def test_only_the_declared_third_party_dependencies_are_used(path: Path) -> None:
    """Catches a dependency added to the venv but never declared.

    The import name of a distribution is not always its package name, so the
    mapping is spelled out rather than guessed.
    """
    import_names_of_allowed = {"bip_utils", "coincurve", "pydantic", "psycopg"}
    stdlib_and_local = {"deriver"}

    third_party = {
        module
        for module in imported_root_modules(path)
        if module not in stdlib_and_local and module not in _STDLIB_ALLOWLIST
    }
    undeclared = third_party - import_names_of_allowed

    assert not undeclared, f"{path.name} imports undeclared package(s): {sorted(undeclared)}"


#: Standard-library modules the deriver legitimately uses. Deliberately an
#: allowlist and not `sys.stdlib_module_names`: keeping it explicit means a new
#: stdlib import shows up in a diff and gets a moment's thought, which is how
#: `socket` or `asyncio` would otherwise sneak in.
_STDLIB_ALLOWLIST = frozenset(
    {
        "__future__",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "hmac",
        "logging",
        "os",
        "pathlib",
        "re",
        "typing",
        "uuid",
        "collections",
        "contextlib",
        "decimal",
        "functools",
        "itertools",
        "string",
        "sys",
        "time",
        "traceback",
    }
)


def test_pyproject_dependency_list_has_not_grown() -> None:
    """The isolation is only mechanical if the manifest stays minimal.

    ``deriver/pyproject.toml`` says the list "MUST STAY EXACTLY
    {bip-utils, coincurve, pydantic, psycopg}". This is that sentence, executed.
    """
    manifest = tomllib.loads((DERIVER_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        requirement.split("==")[0].split(">=")[0].split("[")[0].strip()
        for requirement in manifest["project"]["dependencies"]
    }

    assert declared == ALLOWED_DEPENDENCIES


def test_deriver_has_its_own_manifest_separate_from_the_root() -> None:
    """Two manifests is what makes `pip install ./deriver` unable to see web3.

    If the deriver ever collapsed back into the root package, the isolation
    would silently become a matter of discipline again.
    """
    root = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "deriver" not in root["tool"]["setuptools"]["packages"]
    assert "web3" in " ".join(root["project"]["dependencies"])  # the root may have it
    assert (DERIVER_DIR / "pyproject.toml").is_file()


def test_no_module_reads_an_xpub_from_the_environment() -> None:
    """TZ 5.8/T4 rules out env vars for the key: `docker inspect`, `/proc`, core dumps.

    The credential loader is allowed to read ``CREDENTIALS_DIRECTORY`` — a
    path, not a secret. Anything reading a variable whose name suggests it
    holds the key itself is a regression.
    """
    banned = {"ACCOUNT_XPUB", "XPUB", "NOTCHSTAVE_XPUB", "DERIVER_XPUB"}

    for path in production_source_files():
        source = path.read_text(encoding="utf-8")
        for name in banned:
            assert f'"{name}"' not in source, f"{path.name} reads {name} from the environment"
            assert f"'{name}'" not in source, f"{path.name} reads {name} from the environment"
