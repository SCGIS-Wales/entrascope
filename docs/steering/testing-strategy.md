# Testing strategy

## Layout

`tests/` mirrors `src/entrascope/`, one test module per source module, plus
`test_guards.py` for the five structural guards. Fixtures live in
`tests/conftest.py` and static payloads in `tests/fixtures/`.

## Mocking

`responses` intercepts every outbound call, including those azure-core makes on
behalf of azure-identity and azure-monitor-query, which is one of the reasons
the transport is requests. Graph payloads come from JSON fixtures that carry no
real tenant identifier, object id or user principal name. A test asserts the
fixture directory contains no such identifier, because the repository is
public.

JWKS responses are mocked the same way, and tokens are minted locally with an
RS256 key pair generated in the fixture, so the token tests need no network and
no tenant.

## Credential fixtures

A fixture writes a credential file into a temporary home directory and sets its
mode, one variant correct at 0600 in a 0700 directory, others deliberately
wrong at 0644 or inside a 0755 directory. The permission tests assert refusal
and assert the remediation text names the correct `chmod`.

## The MCP surface

The FastMCP in memory client lists the tools and calls them, so the tool
surface is tested without a transport. A further test asserts that an MCP tool
result and the corresponding CLI `--output json` payload are identical, which
is what keeps `render.py` honest.

## Authorisation tests

The remote server tests mint RS256 tokens locally and assert each rejection
path separately: no token, wrong audience, wrong issuer, expired, and missing
scope. A transport level assertion proves that no request to the Graph host
ever carries the caller's token.

## Coverage

90 percent on `src/`, enforced as a hard failure from phase two onward. The
figure is a floor and not a target. A module with a low branch count and no
test is a gap even when the percentage looks healthy.

## End to end against a real tenant

The suite is offline, and some things only a tenant can tell you. An end to end
run creates one application of every kind, gives one a secret and another a
certificate, exercises the flows that can be driven without a browser, reads
the events back through the command line, and removes everything it made.

It is deliberately not part of the suite: it needs a tenant, it writes to a
directory, and it takes minutes. It is run by hand when the classification or
the error mapping changes, and whatever it finds becomes an offline test. The
codes it observed are now covered by name in `test_errors.py`, and the
classification rules it corrected by fixtures in `test_discovery.py`.

## The README

Documentation drifts the moment a command is renamed, and nobody notices until
somebody types what it said. Every entrascope command inside a fenced block in
the README is resolved against the real command line, with its real options,
and the application types, the output formats, the authentication sources and
the top level commands are each checked against the code that defines them.
Links to files in the repository are checked to exist.

## Speed

The whole suite runs offline and finishes in seconds. A test that needs a
tenant is not a unit test and does not belong in the suite. Any test that could
hang carries the global 120 second timeout.
