# Release and publishing

## Branch and merge protocol

One phase is one pull request. Branch from an up to date `main` as
`phase/NN-slug`, commit in conventional form, run the full local gate before
pushing, open the pull request, wait for every check to pass, then squash merge
and delete the branch. Nothing is committed to `main` directly. No pull request
merges on red, and `[skip ci]` never appears on a hand written commit.

## The pipeline

One workflow, `ci.yml`, named CI/CD Pipeline, carrying both integration and
release, with read only permissions at the top level and write granted per job.
A separate `codeql.yml` runs weekly. `dependabot.yml` groups the dependency
families that move together.

Jobs, in the phase each arrives:

| Job | Purpose | Phase |
| --- | --- | --- |
| lint | ruff check and ruff format check | 0 |
| typecheck | mypy strict | 0 |
| guards | the five structural guards, as their own check | 0 |
| test | pytest with coverage on Python 3.14 | 0 |
| security | pip-audit and a CycloneDX SBOM artifact | 0 |
| build | python -m build and twine check | 0 |
| install-test | install the wheel in a clean environment and run the console script | 5 |
| mcp-smoke | start the stdio server and list the tools | 7 |
| docker | buildx and push to the GitHub container registry | 8 |
| auto-tag | semver patch bump, commit, tag, push, build | 9 |
| publish-testpypi | Trusted Publishing dry run | 9 |
| publish-pypi | Trusted Publishing with a retry | 9 |
| release | a GitHub release from the same artefact | 9 |

Everything up to and including build is a required check on a pull request.

## Versioning and tagging

Semantic versioning with tags of the form `vMAJOR.MINOR.PATCH`. On a push to
`main` the auto-tag job reads the latest tag, computes the next patch version,
rewrites the version in `pyproject.toml` and `src/entrascope/__init__.py`,
commits with `[skip ci]`, tags, pushes, and exports the version as a job output
so the publish jobs in the same run consume it. No second workflow run is
triggered by the tag push.

The release jobs are gated on two repository variables, so that a merge to main
publishes nothing until you decide otherwise:

| Variable | Set it to | Effect |
| --- | --- | --- |
| `ENABLE_RELEASE` | `true` | auto-tag, publish to PyPI and create the release |
| `ENABLE_TESTPYPI` | `true` | also run the TestPyPI dry run first |

`ENABLE_TESTPYPI` is separate because TestPyPI needs its own pending publisher.
Without one that job would fail and block the real publish, so it is skipped
rather than assumed. Set both variables with:

```bash
gh variable set ENABLE_RELEASE --body true --repo SCGIS-Wales/entrascope
gh variable set ENABLE_TESTPYPI --body true --repo SCGIS-Wales/entrascope
```

The first release takes the version already in `pyproject.toml`, so the first
tag is `v0.1.0`. Every merge after that bumps the patch version.

## Trusted Publishing

PyPI Trusted Publishing over OpenID Connect. No API tokens anywhere. The
publish jobs carry `id-token: write` and no username or password. Attestations
and Sigstore signing happen by default.

The PyPI pending publisher is registered, with these values:

| Field | Value |
| --- | --- |
| PyPI project name | `entrascope` |
| Owner | `SCGIS-Wales` |
| Repository name | `entrascope` |
| Workflow name | `ci.yml` |
| Environment name | not set |

Leaving the environment unset is a valid configuration. It means PyPI accepts a
token from that workflow whichever GitHub environment the job runs in, so the
`pypi` environment protection still applies on our side without having to
match a name on theirs.

Still outstanding before the first tag:

1. A pending publisher on test.pypi.org with the same four values, if the
   TestPyPI dry run is to stay in the pipeline. Without it that job fails and
   blocks the real publish.
2. In GitHub, an environment named `pypi` with protection rules, required
   reviewers and a tag restriction, and one named `testpypi` if the dry run
   stays.

On first successful publish the pending publisher becomes a normal publisher.

## The publish retry

Publishing occasionally fails on a transient upstream error, most often a 5xx
from the Sigstore Rekor transparency log while generating attestations. The
publish job therefore makes up to three attempts with 30 and 60 second backoff.
Every attempt uses the official action with `skip-existing`, so files uploaded
by a partial attempt are skipped rather than causing a hard failure. The first
two attempts are `continue-on-error`, the third is not, so a persistent failure
still fails the job.

## Changelog

Keep a Changelog format with an Unreleased section promoted on each tag.
