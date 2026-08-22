"""Microsoft Graph client tests."""

from __future__ import annotations

from typing import Any

import pytest
import responses

from entrascope.config import Config, load_config
from entrascope.graph import (
    NEXT_LINK,
    collection_params,
    fan_out_objects,
    get_collection,
    get_object,
    graph_path,
    graph_root,
    graph_url,
    token_provider,
)
from entrascope.http import build_session
from entrascope.models import ApiCallError

ROOT = "https://graph.microsoft.com/v1.0"


@pytest.fixture
def config() -> Config:
    """Return the repository configuration."""
    return load_config()


# framework contract: azure-core expresses an access token as an object with a
# token and an expiry, so the double must present the same two attributes.
class FakeToken:
    def __init__(self, token: str, expires_on: float) -> None:
        self.token = token
        self.expires_on = expires_on


# framework contract: azure-core expresses a credential as an object with a
# get_token method, so the double must present the same method.
class FakeCredential:
    def __init__(self, expiry: float = 10_000.0) -> None:
        self.calls = 0
        self.expiry = expiry

    def get_token(self, *scopes: str, **kwargs: Any) -> FakeToken:
        self.calls += 1
        return FakeToken(f"token-{self.calls}", self.expiry)


def test_graph_root_and_paths_come_from_configuration(config: Config) -> None:
    """The root and every path are configured, not literal."""
    assert graph_root(config) == ROOT
    assert graph_root(config, beta=True).endswith("/beta")
    assert graph_path(config, "applications") == "/applications"
    by_id = graph_path(config, "application_by_id", {"object_id": "abc"})
    assert by_id.endswith("/abc")
    assert graph_url(config, "applications") == f"{ROOT}/applications"


def test_unknown_endpoint_lists_the_configured_ones(config: Config) -> None:
    """Asking for a path that is not configured says which are."""
    with pytest.raises(ApiCallError) as raised:
        graph_path(config, "no_such_path")
    assert "applications" in raised.value.error.message


def test_collection_params_use_the_configured_page_size(config: Config) -> None:
    """Paging defaults come from configuration."""
    params = collection_params(config)
    assert params["$top"] == config.retry.paging.page_size
    detailed = collection_params(
        config, select=["id", "appId"], filter_expression="a eq 1", order_by="id"
    )
    assert detailed["$select"] == "id,appId"
    assert detailed["$filter"] == "a eq 1"
    assert detailed["$orderby"] == "id"


@responses.activate
def test_graph_list_apps(config: Config) -> None:
    """A collection request returns every item."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"value": [{"id": "1"}, {"id": "2"}]},
        status=200,
    )
    apps = get_collection(build_session(config), config, "applications")
    assert [app["id"] for app in apps] == ["1", "2"]


@responses.activate
def test_graph_paging_follows_the_next_link(config: Config) -> None:
    """Paging follows the next link and does not repeat the query parameters."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"value": [{"id": "1"}], NEXT_LINK: f"{ROOT}/applications?$skiptoken=x"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"value": [{"id": "2"}]},
        status=200,
    )
    apps = get_collection(build_session(config), config, "applications")
    assert [app["id"] for app in apps] == ["1", "2"]
    assert "top=999" in (responses.calls[0].request.url or "")
    assert "top=" not in (responses.calls[1].request.url or "")


@responses.activate
def test_paging_stops_at_the_configured_ceiling(config: Config) -> None:
    """A collection that never ends is bounded by the page ceiling."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"value": [{"id": "1"}], NEXT_LINK: f"{ROOT}/applications"},
        status=200,
    )
    paging = config.retry.paging.model_copy(update={"max_pages": 3})
    limited = config.model_copy(
        update={"retry": config.retry.model_copy(update={"paging": paging})}
    )
    apps = get_collection(build_session(limited), limited, "applications")
    assert len(apps) == 3


@responses.activate
def test_graph_throttle_retry_after(config: Config) -> None:
    """A 429 is retried by the transport adapter and then succeeds."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"error": {"code": "TooManyRequests", "message": "slow down"}},
        status=429,
        headers={"Retry-After": "0"},
    )
    responses.add(
        responses.GET, f"{ROOT}/applications", json={"value": [{"id": "1"}]}, status=200
    )
    apps = get_collection(build_session(config), config, "applications")
    assert len(apps) == 1
    assert len(responses.calls) == 2


@responses.activate
def test_get_object_returns_one_item(config: Config) -> None:
    """A single object request returns the decoded body."""
    responses.add(
        responses.GET, f"{ROOT}/applications/abc", json={"id": "abc"}, status=200
    )
    body = get_object(
        build_session(config), config, "application_by_id", {"object_id": "abc"}
    )
    assert body["id"] == "abc"


@responses.activate
def test_single_object_response_is_yielded_by_paging(config: Config) -> None:
    """An endpoint that returns an object rather than a collection still yields it."""
    responses.add(
        responses.GET, f"{ROOT}/organization", json={"id": "tenant"}, status=200
    )
    rows = get_collection(build_session(config), config, "organization")
    assert rows[0]["id"] == "tenant"


def test_token_acquisition_is_cached(config: Config) -> None:
    """A valid token is reused rather than re-acquired."""
    credential = FakeCredential(expiry=10_000.0)
    provide = token_provider(credential, "scope", clock=lambda: 0.0)
    assert provide() == "token-1"
    assert provide() == "token-1"
    assert credential.calls == 1


def test_token_cache_refreshes_before_expiry(config: Config) -> None:
    """A token close to expiry is renewed rather than used."""
    credential = FakeCredential(expiry=100.0)
    provide = token_provider(credential, "scope", clock=lambda: 0.0)
    assert provide() == "token-1"
    later = token_provider(credential, "scope", clock=lambda: 99.0)
    assert later() == "token-2"


@responses.activate
def test_fan_out_objects_skips_a_failing_object(config: Config) -> None:
    """One object failing does not fail the whole fan out."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications/good/owners",
        json={"value": [{"id": "owner"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/applications/bad/owners",
        json={"error": {"code": "Authorization_RequestDenied", "message": "no"}},
        status=403,
    )
    results = fan_out_objects(
        ["good", "bad"], config, "application_owners", lambda: "token"
    )
    assert results[0][0]["id"] == "owner"
    assert results[1] == ()


@responses.activate
def test_a_limit_caps_the_rows_not_the_page_size(config: Config) -> None:
    """A caller asking for three rows gets three rows, not three per page.

    Graph treats $top as a page size and keeps paging beyond it, so the limit
    has to be applied here.
    """
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={
            "value": [{"id": str(index)} for index in range(5)],
            NEXT_LINK: f"{ROOT}/applications?$skiptoken=x",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"value": [{"id": str(index)} for index in range(5, 10)]},
        status=200,
    )
    rows = get_collection(build_session(config), config, "applications", limit=3)
    assert [row["id"] for row in rows] == ["0", "1", "2"]


@responses.activate
def test_no_limit_returns_everything(config: Config) -> None:
    """Without a limit every page is returned."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"value": [{"id": "1"}, {"id": "2"}]},
        status=200,
    )
    assert len(get_collection(build_session(config), config, "applications")) == 2


def test_page_size_is_omitted_where_graph_refuses_it(config: Config) -> None:
    """Some collections reject a custom page size, and those are configured."""
    from entrascope.graph import accepts_page_size

    assert not accepts_page_size(config, "subscribed_skus")
    assert accepts_page_size(config, "applications")
    assert "$top" not in collection_params(config, page_size=False)


def test_a_quote_cannot_escape_a_filter_literal() -> None:
    """A value is matched by the filter, it does not get to rewrite it."""
    from entrascope.graph import odata_literal

    assert odata_literal("o'brien") == "o''brien"
    assert odata_literal("x' or startswith(appId,'") == "x'' or startswith(appId,''"


def test_control_characters_never_reach_a_filter() -> None:
    """Nothing legitimate in a name or an identifier is a control character."""
    from entrascope.graph import odata_literal

    assert odata_literal("name\x00\x1bhere") == "namehere"


def test_a_filter_value_is_bounded() -> None:
    """A value of unbounded length is a mistake or an attack, not a name."""
    from entrascope.graph import MAX_FILTER_VALUE, odata_literal

    assert len(odata_literal("a" * 5000)) == MAX_FILTER_VALUE


def test_two_threads_missing_the_token_cache_fetch_once(config: Config) -> None:
    """The provider is shared by every worker in a fan out.

    Two of them missing the cache at the same moment would each ask the
    authority for a token nobody needed.
    """
    import threading

    credential = FakeCredential(expiry=10_000.0)
    provide = token_provider(credential, "scope", clock=lambda: 0.0)
    barrier = threading.Barrier(8, timeout=10)

    def ask() -> str:
        barrier.wait()
        return provide()

    threads = [threading.Thread(target=ask) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert credential.calls == 1
