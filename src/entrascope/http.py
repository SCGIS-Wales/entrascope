"""The HTTP transport.

This is the only module that imports ``requests``, which a guard test enforces.
Every outbound call the tool makes passes through :func:`request`, so timeouts,
retry, the user agent and the access log are configured in exactly one place.

The transport is synchronous. azure-core, which azure-identity and
azure-monitor-query sit on, already uses requests, so choosing it here gives one
HTTP stack rather than two. Concurrency, where it is needed, is a thread pool
over independent sessions.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TypeVar

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from urllib3.util.retry import Retry

from entrascope import __version__
from entrascope.config import Config, NetworkSettings
from entrascope.logger import get_logger
from entrascope.models import ApiCallError, ApiError, NetworkTrust

log = get_logger(__name__)

#: The session type, re-exported so that no other module imports requests.
Session = requests.Session

Item = TypeVar("Item")
Result = TypeVar("Result")

#: Headers that name the server side identifier of a failed request.
CORRELATION_HEADERS = ("client-request-id", "request-id", "x-ms-correlation-request-id")
REQUEST_ID_HEADERS = ("x-ms-request-id", "request-id")


def environment(environ: Mapping[str, str] | None = None) -> Mapping[str, str]:
    """Return the environment to read, which the tests replace."""
    return os.environ if environ is None else environ


def resolve_proxies(
    settings: NetworkSettings, environ: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return the forward proxies named in the environment.

    requests honours the conventional variables on its own when the session
    trusts the environment. They are resolved explicitly as well so that the
    doctor command can report exactly what is in force, which is what an
    engineer behind a corporate proxy needs to see.
    """
    source = environment(environ)
    proxies: dict[str, str] = {}
    for name in settings.proxy_variables:
        value = source.get(name, "").strip()
        if not value:
            continue
        scheme = name.split("_")[0].lower()
        key = "all" if scheme == "all" else scheme
        proxies.setdefault(key, value)
    for name in settings.no_proxy_variables:
        value = source.get(name, "").strip()
        if value:
            proxies.setdefault("no_proxy", value)
            break
    return proxies


def resolve_ca_trust(
    settings: NetworkSettings, environ: Mapping[str, str] | None = None
) -> tuple[str | bool, str]:
    """Return what to verify TLS against, and where that came from.

    A bundle file wins over a directory. requests recognises two of these
    variables on its own but not the OpenSSL ones, so all of them are resolved
    here and applied explicitly. Verification is never silently disabled: when
    nothing is configured the certifi bundle that requests ships is used.
    """
    if not settings.verify_tls:
        return False, "TLS verification is disabled in configuration"
    source = environment(environ)
    for name in settings.ca_bundle_variables:
        value = source.get(name, "").strip()
        if value and Path(value).is_file():
            return value, name
    for name in settings.ca_directory_variables:
        value = source.get(name, "").strip()
        if value and Path(value).is_dir():
            return value, name
    return True, "the default certificate bundle"


def network_trust(
    config: Config, environ: Mapping[str, str] | None = None
) -> NetworkTrust:
    """Describe the proxy and certificate trust in force, for the doctor report."""
    settings = config.retry.network
    verify, origin = resolve_ca_trust(settings, environ)
    proxies = resolve_proxies(settings, environ)
    return NetworkTrust(
        trust_environment=settings.trust_environment,
        verify=verify if isinstance(verify, str) else "",
        verify_enabled=verify is not False,
        verify_source=origin,
        proxies=tuple(sorted(f"{key}={value}" for key, value in proxies.items())),
    )


def verify_setting(
    config: Config, environ: Mapping[str, str] | None = None
) -> str | bool:
    """Return the TLS verification setting for any client, ours or the SDK's.

    azure-identity and azure-monitor-query sit on azure-core, whose default
    transport is requests, so they take the same value under the name
    connection_verify.
    """
    verify, _ = resolve_ca_trust(config.retry.network, environ)
    return verify


def build_retry(config: Config) -> Retry:
    """Build the retry policy from configuration."""
    settings = config.retry.retry
    # framework contract: urllib3 expresses its retry policy as an object. Every
    # value comes from config/retry.yaml and no logic lives here.
    return Retry(
        total=settings.total,
        connect=settings.connect,
        read=settings.read,
        status=settings.status,
        backoff_factor=settings.backoff_factor,
        backoff_max=settings.backoff_max_seconds,
        respect_retry_after_header=settings.respect_retry_after_header,
        status_forcelist=list(settings.status_forcelist),
        allowed_methods=frozenset(settings.allowed_methods),
        raise_on_status=False,
    )


def user_agent(config: Config) -> str:
    """Return the user agent string, with the running version substituted."""
    return config.retry.http.user_agent.format(version=__version__)


def timeouts(config: Config) -> tuple[float, float]:
    """Return the connect and read timeouts."""
    return (
        config.retry.http.connect_timeout_seconds,
        config.retry.http.read_timeout_seconds,
    )


def bearer_auth(
    provider: Callable[[], str],
) -> Callable[[PreparedRequest], PreparedRequest]:
    """Return a requests auth callable that fetches a token for every request.

    The token is never held on the session, so a refresh inside the provider
    takes effect on the next call without rebuilding anything.
    """

    def apply(prepared: PreparedRequest) -> PreparedRequest:
        prepared.headers["Authorization"] = f"Bearer {provider()}"
        return prepared

    return apply


def build_session(
    config: Config,
    token_provider: Callable[[], str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> requests.Session:
    """Build a session carrying the retry policy, pool sizes and user agent.

    The session honours forward web proxies from the environment and verifies
    TLS against a certificate authority bundle or directory named there, so
    that entrascope works unchanged behind a corporate proxy performing TLS
    inspection.
    """
    # framework contract: requests expresses configuration as Session and
    # HTTPAdapter objects. They are treated as configuration and carry no logic.
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=build_retry(config),
        pool_connections=config.retry.http.pool_connections,
        pool_maxsize=config.retry.http.pool_maxsize,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {"User-Agent": user_agent(config), "Accept": "application/json"}
    )
    network = config.retry.network
    session.trust_env = network.trust_environment
    verify, _ = resolve_ca_trust(network, environ)
    session.verify = verify
    session.proxies.update(resolve_proxies(network, environ))
    if token_provider is not None:
        session.auth = bearer_auth(token_provider)
    return session


@contextmanager
def session_scope(
    config: Config, token_provider: Callable[[], str] | None = None
) -> Iterator[requests.Session]:
    """Yield a session and close it afterwards."""
    session = build_session(config, token_provider)
    try:
        yield session
    finally:
        session.close()


def header_value(headers: Mapping[str, str], names: Sequence[str]) -> str:
    """Return the first header present out of several candidate names."""
    for name in names:
        value = headers.get(name)
        if value:
            return value
    return ""


def error_payload(response: requests.Response) -> tuple[str, str]:
    """Extract the error code and message from a failed response body.

    Microsoft Graph, Azure Resource Manager and the token endpoint each use a
    different shape, so all three are recognised.
    """
    try:
        body = response.json()
    except ValueError:
        return "", response.text[:500]
    if not isinstance(body, Mapping):
        return "", str(body)[:500]
    inner = body.get("error")
    if isinstance(inner, Mapping):
        return str(inner.get("code", "")), str(inner.get("message", ""))
    if isinstance(inner, str):
        # The token endpoint returns error and error_description as strings.
        return inner, str(body.get("error_description", ""))
    return "", str(body)[:500]


def to_api_error(response: requests.Response, source: str) -> ApiError:
    """Turn a failed response into the structured error every surface renders."""
    code, message = error_payload(response)
    return ApiError(
        status=response.status_code,
        code=code,
        message=message,
        correlation_id=header_value(response.headers, CORRELATION_HEADERS),
        request_id=header_value(response.headers, REQUEST_ID_HEADERS),
        source=source,
    )


def request(
    session: requests.Session,
    method: str,
    url: str,
    config: Config,
    *,
    params: Mapping[str, Any] | None = None,
    json_body: Any = None,
    source: str = "graph",
) -> requests.Response:
    """Perform one HTTP call, logging it and raising on a failure status.

    Retry and backoff are handled by the adapter. What is left here is the
    timeout, the access log line and the conversion of a failure into the one
    structured error the whole tool uses.
    """
    started = time.monotonic()
    response = session.request(
        method,
        url,
        params=dict(params) if params else None,
        json=json_body,
        timeout=timeouts(config),
    )
    elapsed_ms = round((time.monotonic() - started) * 1000)
    log.debug(
        "%s %s returned %s",
        method,
        url,
        response.status_code,
        extra={"elapsed_ms": elapsed_ms, "api": source},
    )
    if not response.ok:
        error = to_api_error(response, source)
        log.warning(
            "%s call failed: %s",
            source,
            error.summary(),
            extra={"elapsed_ms": elapsed_ms, "api": source, "status": error.status},
        )
        raise ApiCallError(error)
    return response


def get_json(
    session: requests.Session,
    url: str,
    config: Config,
    *,
    params: Mapping[str, Any] | None = None,
    source: str = "graph",
) -> dict[str, Any]:
    """Perform one GET and return the decoded body."""
    response = request(session, "GET", url, config, params=params, source=source)
    body = response.json()
    if not isinstance(body, dict):
        raise ApiCallError(
            ApiError(
                status=response.status_code,
                code="UnexpectedBody",
                message="The response body was not a JSON object.",
                source=source,
            )
        )
    return body


def fan_out[Item, Result](
    items: Sequence[Item],
    work: Callable[[requests.Session, Item], Result],
    config: Config,
    token_provider: Callable[[], str] | None = None,
) -> tuple[Result, ...]:
    """Run one function over many items concurrently, preserving order.

    Each worker holds its own session, which is the thread safety boundary
    requests documents. The worker count comes from configuration.
    """
    if not items:
        return ()
    workers = max(1, min(config.retry.concurrency.max_workers, len(items)))
    sessions = [build_session(config, token_provider) for _ in range(workers)]
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            indexed = list(enumerate(items))
            results = pool.map(
                lambda pair: work(sessions[pair[0] % workers], pair[1]), indexed
            )
            return tuple(results)
    finally:
        for session in sessions:
            session.close()
