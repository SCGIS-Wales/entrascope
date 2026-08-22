"""The README has to be true.

Documentation drifts the moment a command is renamed, and nobody notices until
somebody types what it said. Every entrascope command the README shows is
resolved here against the real command line, with its real options.
"""

from __future__ import annotations

import re
import shlex

import click
import pytest

from entrascope.cli import cli
from tests.conftest import REPO_ROOT

#: A line inside a fenced block that invokes this tool.
INVOCATION = re.compile(r"^\s*entrascope\b(.*)$")

#: Words that stand for something the reader supplies.
PLACEHOLDER = re.compile(r"^<.*>$")


def readme() -> str:
    """Return the README."""
    return (REPO_ROOT / "README.md").read_text(encoding="utf-8")


def fenced_blocks() -> list[str]:
    """Return the contents of every fenced code block.

    Only what is inside a fence is something to be typed. Prose that happens to
    begin with the name of the tool is a sentence.
    """
    blocks: list[str] = []
    inside = False
    current: list[str] = []
    for line in readme().splitlines():
        if line.startswith("```"):
            if inside:
                blocks.append("\n".join(current))
                current = []
            inside = not inside
            continue
        if inside:
            current.append(line)
    return blocks


def invocations() -> list[str]:
    """Return every entrascope command line the README shows."""
    found: list[str] = []
    for block in fenced_blocks():
        for line in block.splitlines():
            # Strip a trailing comment, which the examples use to explain each
            # one, and anything after a shell operator.
            text = line.split("#", 1)[0].split("&&")[0].split("|")[0]
            match = INVOCATION.match(text)
            if match:
                found.append(f"entrascope{match.group(1)}".strip())
    return found


def resolve(tokens: list[str]) -> tuple[click.Command, list[str]]:
    """Walk the command tree, returning the command and what is left."""
    command: click.Command = cli
    remaining = list(tokens)
    context = click.Context(cli)
    while remaining and isinstance(command, click.Group):
        candidate = command.get_command(context, remaining[0])
        if candidate is None:
            break
        command = candidate
        remaining.pop(0)
    return command, remaining


def option_names(command: click.Command) -> set[str]:
    """Return every option the command accepts, including the global ones."""
    names: set[str] = set()
    for parameter in [*cli.params, *command.params]:
        names.update(getattr(parameter, "opts", []))
        names.update(getattr(parameter, "secondary_opts", []))
    return names


def test_the_readme_shows_at_least_the_main_commands() -> None:
    """A test over an empty list would pass and prove nothing."""
    assert len(invocations()) >= 20


@pytest.mark.parametrize("line", invocations(), ids=lambda line: line)
def test_every_command_in_the_readme_exists(line: str) -> None:
    """Somebody typing what the README says must not be told it does not exist."""
    tokens = shlex.split(line)[1:]
    command, remaining = resolve(tokens)
    if command is cli and tokens:
        pytest.fail(f"{tokens[0]!r} is not a command")
    accepted = option_names(command)
    for token in remaining:
        if not token.startswith("-"):
            continue
        name = token.split("=", 1)[0]
        assert name in accepted, f"{name} is not an option of {command.name}"


@pytest.mark.parametrize("line", invocations(), ids=lambda line: line)
def test_no_command_in_the_readme_takes_a_placeholder_it_will_not_accept(
    line: str,
) -> None:
    """A placeholder stands for a value, so the command must take one."""
    tokens = shlex.split(line)[1:]
    command, remaining = resolve(tokens)
    placeholders = [item for item in remaining if PLACEHOLDER.match(item)]
    if not placeholders:
        return
    takes_values = any(isinstance(item, click.Argument) for item in command.params)
    previous = remaining[remaining.index(placeholders[0]) - 1]
    assert takes_values or previous.startswith("-"), (
        f"{command.name} takes no argument, so {placeholders[0]} has nowhere to go"
    )


def test_the_readme_names_the_output_formats_that_exist() -> None:
    """The table in the README is the list somebody will rely on."""
    from entrascope.render import OUTPUT_FORMATS

    body = readme()
    for name in OUTPUT_FORMATS:
        assert f"`{name}`" in body, f"{name} is missing from the README"


def test_the_readme_names_the_authentication_sources_that_exist() -> None:
    """Naming one that does not exist sends somebody looking for it."""
    from entrascope.models import AUTH_SOURCE_ORDER

    body = readme()
    for source in AUTH_SOURCE_ORDER:
        assert f"`{source}`" in body, f"{source} is missing from the README"


def test_the_readme_links_to_files_that_are_there() -> None:
    """A dead link in the first thing anybody reads."""
    body = readme()
    for target in re.findall(r"\]\((?!https?:)([^)#]+)\)", body):
        assert (REPO_ROOT / target).exists(), f"{target} does not exist"


def test_the_readme_names_every_application_type() -> None:
    """The type table is what somebody reads before typing --type."""
    from typing import get_args

    from entrascope.models import ApplicationType

    body = readme()
    for name in get_args(ApplicationType):
        if name == "unknown":
            continue
        assert f"`{name}`" in body, f"{name} is missing from the README"


def test_the_readme_names_every_top_level_command() -> None:
    """A command nobody is told about may as well not exist."""
    body = readme()
    for name, command in cli.commands.items():
        if command.hidden:
            continue
        assert f"entrascope {name}" in body or f"`{name}`" in body, (
            f"{name} is missing from the README"
        )


def test_the_readme_does_not_promise_an_extra_that_is_not_needed() -> None:
    """The servers are part of the ordinary install, and saying otherwise sends
    somebody to add something they already have."""
    assert "pip install 'entrascope[mcp]'" not in readme()
