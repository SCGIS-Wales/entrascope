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

## Speed

The whole suite runs offline and finishes in seconds. A test that needs a
tenant is not a unit test and does not belong in the suite. Any test that could
hang carries the global 120 second timeout.
