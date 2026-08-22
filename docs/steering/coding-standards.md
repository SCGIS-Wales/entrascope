# Coding standards

## Functional rules

No classes for application logic. Pure functions and function composition.
`typing.NamedTuple` or frozen dataclasses for immutable data transfer objects
only. No object oriented service classes, no inheritance hierarchies, no
mutable module level state.

Where a third party framework requires a class, instantiate or subclass it
inside a factory function and mark it:

```python
# framework contract: requests requires a Session object; all behaviour stays
# in free functions and this object is treated as configuration.
```

A guard test parses the abstract syntax tree of every module and fails the
build on any class definition that is not permitted. A class is permitted when
it carries that comment in the five lines above it, when it is a data transfer
object deriving from `NamedTuple`, or when it derives from a class in the same
module that is itself permitted. The last rule is what lets one comment cover a
family of schema models or exception types.

## Typing

PEP 484 hints everywhere, PEP 585 built in generics (`list[str]`, not
`List[str]`), PEP 604 unions (`str | None`, not `Optional[str]`).
`from __future__ import annotations` at the top of every module. `mypy --strict`
must pass with no ignores, and any unavoidable ignore carries a comment
explaining it.

## Prose

British Oxford English throughout: organise, authorise, recognise, colour, and
licence as a noun with license as a verb. This applies to documentation,
docstrings, help text, comments, log messages and commit messages.

Avoid dash and hyphen punctuation in prose. Write two sentences, or use a
comma. Hyphens inside CLI flags, identifiers, package names, file names and
URLs are syntax and are correct there.

Docstrings follow PEP 257: a one line summary in the imperative mood, a blank
line, then detail if detail is needed.

## Imports

Standard library, then third party, then first party, each block alphabetised.
ruff enforces this. No wildcard imports. No conditional imports except where a
platform genuinely requires one.

## Tooling

`ruff check` and `ruff format --check` for lint and formatting, line length 88.
`mypy --strict` for types. Both run in continuous integration and in the
pre-commit hooks. The build fails on any finding.

## The five guards

1. No endpoint, table name or documentation URL literal in `src/`.
2. No class without a framework contract comment.
3. No secret in any command or tool output.
4. `requests` imported only in `http.py`, `httpx` imported nowhere.
5. No direct `logging.getLogger` call, and no `print` outside `render.py`.
