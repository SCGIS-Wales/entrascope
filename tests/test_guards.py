"""The five structural guards from docs/steering/tasks.md.

These run as their own continuous integration check so that a breach is named
on the pull request rather than buried in the wider test run.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from entrascope.cli import cli
from tests.conftest import SENTINEL_SECRET, source_files

FRAMEWORK_CONTRACT = "# framework contract:"

#: Modules allowed to import the HTTP library, and to call print.
HTTP_MODULE = "http.py"
RENDER_MODULE = "render.py"
LOGGER_MODULE = "logger.py"

#: Literals that are a bare URL scheme rather than an endpoint. Mounting a
#: transport adapter needs the scheme and names no host.
SCHEME_LITERALS = frozenset({"https://", "http://"})

#: Patterns that indicate an endpoint, table name or documentation URL has been
#: written into code rather than into config/.
FORBIDDEN_LITERALS = (
    re.compile(r"https?://"),
    re.compile(r"api://"),
    re.compile(r"\bSigninLogs\b"),
    re.compile(r"\bAuditLogs\b"),
    re.compile(r"\bMicrosoftGraphActivityLogs\b"),
    re.compile(r"\bAADNonInteractiveUserSignInLogs\b"),
    re.compile(r"\bAADServicePrincipalSignInLogs\b"),
)


def string_literals(tree: ast.AST) -> list[str]:
    """Return every string literal in a parsed module, docstrings excluded."""
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        scopes = ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        if isinstance(node, scopes):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr):
                first = body[0].value
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    docstrings.add(id(first))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def imported_modules(tree: ast.AST) -> set[str]:
    """Return the top level name of every module imported."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("path", source_files(), ids=lambda p: p.name)
def test_guard_no_hardcoded_endpoints(path: Path) -> None:
    """Guard one: endpoints, table names and URLs live in config, not in code."""
    tree = ast.parse(path.read_text())
    offenders = [
        literal
        for literal in string_literals(tree)
        if literal not in SCHEME_LITERALS
        for pattern in FORBIDDEN_LITERALS
        if pattern.search(literal)
    ]
    assert not offenders, (
        f"{path.name} contains endpoint or table literals {offenders}. "
        "Move them into config/ and read them through entrascope.config."
    )


#: Base classes that mark a class as an immutable data transfer object, which
#: CLAUDE.md permits without a framework contract comment.
DTO_BASES = frozenset({"NamedTuple", "Enum", "StrEnum", "IntEnum"})


def base_names(node: ast.ClassDef) -> set[str]:
    """Return the names of every base a class declares."""
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def permitted_classes(source: str) -> tuple[set[str], list[str]]:
    """Return the permitted class names in a module, and the offenders.

    A class is permitted when it carries a framework contract comment in the
    five lines above it, when it is a data transfer object, or when it derives
    from a class in the same module that is itself permitted. The last rule is
    what lets one comment cover a family of schema models or exceptions.
    """
    lines = source.splitlines()
    classes = [
        node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ClassDef)
    ]
    permitted: set[str] = set()
    undecided = list(classes)
    while True:
        remaining: list[ast.ClassDef] = []
        for node in undecided:
            preamble = "\n".join(lines[max(0, node.lineno - 6) : node.lineno])
            bases = base_names(node)
            if FRAMEWORK_CONTRACT in preamble or bases & DTO_BASES or bases & permitted:
                permitted.add(node.name)
            else:
                remaining.append(node)
        if len(remaining) == len(undecided):
            return permitted, [node.name for node in remaining]
        undecided = remaining


#: Graph property names that must never be written into a projection in src.
#: Each is a field mapping, which hard rule 3 puts in config/fields.yaml. The
#: list is the properties a projection actually reads, not every camel case
#: word Microsoft uses, because the rule is about mappings rather than about
#: spelling.
MAPPED_PROPERTIES = frozenset(
    {
        "appRoleAssignmentRequired",
        "createdDateTime",
        "keyCredentials",
        "notificationEmailAddresses",
        "passwordCredentials",
        "preferredSingleSignOnMode",
        "preferredTokenSigningKeyThumbprint",
        "requiredResourceAccess",
        "servicePrincipalType",
        "signInAudience",
        "tokenEncryptionKeyId",
    }
)

#: Where a mapping may legitimately be named: the module that reads the
#: configuration files.
MAPPING_EXEMPT = frozenset({"config.py"})


def output_keys(tree: ast.AST) -> set[int]:
    """Return the ids of literals used as keys of a dictionary being built.

    A property name written as a key is this tool choosing what to call a
    field in its own output. The provisioning report does exactly that, on
    purpose, so that a live application can be read back in the vocabulary the
    provisioner creates one with. Only a literal used to read a payload is a
    field mapping.
    """
    keys: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys.update(
                id(key)
                for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            )
    return keys


@pytest.mark.parametrize("path", source_files(), ids=lambda p: p.name)
def test_guard_field_mappings_live_in_configuration(path: Path) -> None:
    """Guard six: a projection reads a property named in config, not in code.

    Hard rule 3 lists field mappings among the things nothing in src may hold.
    A Graph property name written into a module to read a payload is exactly
    that, and it is the kind of thing that drifts quietly: the configuration
    says one thing, the code reads another, and the two disagree for a release
    before anybody notices.
    """
    if path.name in MAPPING_EXEMPT:
        return
    tree = ast.parse(path.read_text())
    keys = output_keys(tree)
    offenders = sorted(
        {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in MAPPED_PROPERTIES
            and id(node) not in keys
        }
    )
    assert not offenders, (
        f"{path.name} reads Graph properties that belong in config/fields.yaml: "
        f"{offenders}"
    )


def test_the_mapping_guard_sees_a_read_and_not_a_key() -> None:
    """The guard must tell a payload being read from a report being written."""
    read = ast.parse('value = payload.get("signInAudience")')
    written = ast.parse('report = {"signInAudience": value}')
    assert not output_keys(read)
    assert len(output_keys(written)) == 1


@pytest.mark.parametrize("path", source_files(), ids=lambda p: p.name)
def test_guard_no_classes(path: Path) -> None:
    """Guard two: no class without a framework contract comment above it."""
    _, offenders = permitted_classes(path.read_text())
    assert not offenders, (
        f"{path.name} defines classes {offenders} without a "
        f'"{FRAMEWORK_CONTRACT}" comment. Application logic belongs in free '
        "functions, and a data transfer object derives from NamedTuple."
    )


def test_guard_no_secrets_in_command_output() -> None:
    """Guard three: no command may echo a secret."""
    runner = CliRunner()
    for command in ("--help", "discover --help", "logs --help", "errors --help"):
        result = runner.invoke(cli, command.split())
        assert result.exit_code == 0, f"{command} exited {result.exit_code}"
        assert SENTINEL_SECRET not in result.output


@pytest.mark.parametrize("path", source_files(), ids=lambda p: p.name)
def test_guard_one_http_stack(path: Path) -> None:
    """Guard four: requests only in http.py, httpx nowhere."""
    imports = imported_modules(ast.parse(path.read_text()))
    assert "httpx" not in imports, (
        f"{path.name} imports httpx. The transport is requests, in {HTTP_MODULE}."
    )
    if path.name != HTTP_MODULE:
        assert "requests" not in imports, (
            f"{path.name} imports requests directly. Every outbound call goes "
            f"through {HTTP_MODULE}."
        )


@pytest.mark.parametrize("path", source_files(), ids=lambda p: p.name)
def test_guard_one_logger(path: Path) -> None:
    """Guard five: one logger factory, and print only in the render module."""
    tree = ast.parse(path.read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]

    if path.name != LOGGER_MODULE:
        direct = [
            node
            for node in calls
            if isinstance(node.func, ast.Attribute) and node.func.attr == "getLogger"
        ]
        assert not direct, (
            f"{path.name} calls logging.getLogger directly. Use "
            f"entrascope.logger.get_logger so redaction and the correlation id "
            "are applied."
        )

    if path.name != RENDER_MODULE:
        prints = [
            node
            for node in calls
            if isinstance(node.func, ast.Name) and node.func.id == "print"
        ]
        assert not prints, (
            f"{path.name} calls print. Rendering belongs in {RENDER_MODULE}."
        )


def test_class_guard_catches_an_unmarked_class() -> None:
    """The class guard is proved against a module that breaks the rule."""
    offending = "class Service:\n    def run(self) -> None: ...\n"
    _, offenders = permitted_classes(offending)
    assert offenders == ["Service"]


def test_class_guard_accepts_a_marked_family() -> None:
    """One framework contract comment covers the classes derived from it."""
    source = (
        "# framework contract: pydantic requires model classes.\n"
        "class Base:\n    pass\n\n\n"
        "class Child(Base):\n    pass\n"
    )
    permitted, offenders = permitted_classes(source)
    assert not offenders
    assert permitted == {"Base", "Child"}


def test_class_guard_accepts_a_named_tuple() -> None:
    """A data transfer object needs no comment."""
    source = "class Row(NamedTuple):\n    value: str\n"
    _, offenders = permitted_classes(source)
    assert not offenders
