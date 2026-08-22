"""Microsoft Graph calls.

Every endpoint comes from ``config/endpoints.yaml``. There is no SDK and no
fluent API, because a class heavy dependency would conflict with the functional
rules and would hide the endpoints the guard test checks for.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from itertools import islice
from typing import Any

from azure.core.credentials import TokenCredential
from azure.core.exceptions import ClientAuthenticationError

from entrascope.config import Config
from entrascope.http import Session, fan_out, get_json
from entrascope.logger import get_logger
from entrascope.models import ApiCallError, ApiError

log = get_logger(__name__)

#: Seconds before expiry at which a cached token is renewed.
TOKEN_REFRESH_MARGIN_SECONDS = 300

#: Key that Graph uses to link to the next page of a collection.
NEXT_LINK = "@odata.nextLink"

#: Key that Graph uses for the items of a collection.
VALUE = "value"


#: Characters that have no business in a filter value and that no legitimate
#: display name or identifier contains.
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")

#: A filter value longer than this is a mistake or an attack, not a name.
MAX_FILTER_VALUE = 256


def odata_literal(value: str) -> str:
    """Return a value safe to place inside a quoted OData filter literal.

    A single quote ends the literal, so an unescaped one lets a value change
    the filter it was meant to be matched by. OData escapes a quote by doubling
    it. Control characters are removed outright, and the length is bounded,
    because neither belongs in a name or an identifier.
    """
    cleaned = CONTROL_CHARACTERS.sub("", value)[:MAX_FILTER_VALUE]
    return cleaned.replace("'", "''")


def graph_root(config: Config, *, beta: bool = False) -> str:
    """Return the versioned Graph root URL."""
    graph = config.endpoints.graph
    version = graph.beta_version if beta else graph.version
    return f"{graph.base_url}/{version}"


def graph_path(
    config: Config, name: str, parameters: Mapping[str, str] | None = None
) -> str:
    """Return one configured Graph path with its placeholders filled in."""
    template = config.endpoints.graph.paths.get(name)
    if template is None:
        available = sorted(config.endpoints.graph.paths)
        raise ApiCallError(
            ApiError(
                status=0,
                code="UnknownEndpoint",
                message=f"No Graph path named {name}. Configured paths: {available}.",
                source="config",
            )
        )
    return template.format(**(parameters or {}))


def graph_url(
    config: Config,
    name: str,
    parameters: Mapping[str, str] | None = None,
    *,
    beta: bool = False,
) -> str:
    """Return the full URL for one configured Graph path."""
    return f"{graph_root(config, beta=beta)}{graph_path(config, name, parameters)}"


def token_provider(
    credential: TokenCredential,
    scope: str,
    clock: Callable[[], float] = time.time,
) -> Callable[[], str]:
    """Return a callable that yields a valid access token, refreshing on expiry.

    The token lives inside the closure rather than in module level state, and
    is renewed a few minutes before it expires so that a long running fan out
    cannot straddle an expiry.
    """
    cache: dict[str, tuple[str, float]] = {}

    def provide() -> str:
        cached = cache.get(scope)
        now = clock()
        if cached is not None and cached[1] - TOKEN_REFRESH_MARGIN_SECONDS > now:
            return cached[0]
        try:
            token = credential.get_token(scope)
        except ClientAuthenticationError as error:
            # The authority refusing us is the failure this tool exists to
            # explain, so it becomes the one structured error rather than a
            # stack trace from a dependency.
            raise ApiCallError(
                ApiError(
                    status=401,
                    code="AuthenticationFailed",
                    message=str(error.message or error),
                    source="token",
                )
            ) from error
        cache[scope] = (token.token, float(token.expires_on))
        log.debug("acquired an access token", extra={"scope": scope})
        return token.token

    return provide


def graph_token_provider(
    config: Config, credential: TokenCredential
) -> Callable[[], str]:
    """Return a token provider for the configured Microsoft Graph scope."""
    return token_provider(credential, config.endpoints.graph.scope)


def arm_token_provider(
    config: Config, credential: TokenCredential
) -> Callable[[], str]:
    """Return a token provider for Azure Resource Manager.

    A Graph token is not accepted by Resource Manager. The audiences differ, so
    the diagnostic settings call needs its own token and its own session.
    """
    return token_provider(credential, config.endpoints.azure.arm_scope)


def page(
    session: Session,
    url: str,
    config: Config,
    *,
    params: Mapping[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield every item of a Graph collection, following the next link.

    Paging is the one piece of retry behaviour that the transport adapter
    cannot express, so it lives here. The page ceiling in configuration bounds
    a runaway collection.
    """
    next_url: str | None = url
    query: Mapping[str, Any] | None = params
    pages = 0
    while next_url is not None:
        body = get_json(session, next_url, config, params=query, source="graph")
        items = body.get(VALUE)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yield item
        elif items is None and body:
            yield body
        pages += 1
        if pages >= config.retry.paging.max_pages:
            log.warning(
                "stopped paging at the configured ceiling of %s pages",
                config.retry.paging.max_pages,
            )
            return
        following = body.get(NEXT_LINK)
        next_url = str(following) if isinstance(following, str) else None
        # The next link already carries the query, so it must not be repeated.
        query = None


def accepts_page_size(config: Config, endpoint: str) -> bool:
    """Return whether one endpoint accepts a custom page size.

    Microsoft Graph refuses $top on a handful of collections with
    Request_UnsupportedQuery, so those are named in configuration rather than
    discovered by failing.
    """
    return endpoint not in config.retry.paging.no_page_size


def collection_params(
    config: Config,
    *,
    select: Sequence[str] | None = None,
    filter_expression: str | None = None,
    top: int | None = None,
    order_by: str | None = None,
    page_size: bool = True,
) -> dict[str, Any]:
    """Build the OData query parameters for a collection request."""
    params: dict[str, Any] = {}
    if page_size:
        params["$top"] = top or config.retry.paging.page_size
    if select:
        params["$select"] = ",".join(select)
    if filter_expression:
        params["$filter"] = filter_expression
    if order_by:
        params["$orderby"] = order_by
    return params


def get_collection(
    session: Session,
    config: Config,
    endpoint: str,
    *,
    select: Sequence[str] | None = None,
    filter_expression: str | None = None,
    top: int | None = None,
    order_by: str | None = None,
    limit: int | None = None,
    beta: bool = False,
    path_parameters: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Return every item of one configured Graph collection.

    A page size and a limit are different things. Graph treats $top as the
    number of items per page and keeps paging beyond it, so a caller asking for
    twelve rows is given twelve rows here rather than every page of twelve.
    """
    url = graph_url(config, endpoint, path_parameters, beta=beta)
    params = collection_params(
        config,
        select=select,
        filter_expression=filter_expression,
        top=top,
        order_by=order_by,
        page_size=accepts_page_size(config, endpoint),
    )
    items = page(session, url, config, params=params)
    if limit is None:
        return tuple(items)
    return tuple(islice(items, max(0, limit)))


def get_object(
    session: Session,
    config: Config,
    endpoint: str,
    path_parameters: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return one Graph object by its configured endpoint."""
    return get_json(
        session, graph_url(config, endpoint, path_parameters), config, source="graph"
    )


def fan_out_objects(
    object_ids: Sequence[str],
    config: Config,
    endpoint: str,
    token: Callable[[], str],
) -> tuple[tuple[dict[str, Any], ...], ...]:
    """Fetch one configured collection for many objects concurrently."""

    def work(session: Session, object_id: str) -> tuple[dict[str, Any], ...]:
        try:
            url = graph_url(config, endpoint, {"object_id": object_id})
            return tuple(page(session, url, config))
        except ApiCallError as error:
            log.warning(
                "skipping %s for %s: %s", endpoint, object_id, error.error.summary()
            )
            return ()

    return fan_out(object_ids, work, config, token)
