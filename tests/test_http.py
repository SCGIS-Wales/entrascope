"""Transport tests: session construction, retry, logging and error shaping."""

from __future__ import annotations

from typing import Any

import pytest
import requests
import responses

from entrascope import __version__
from entrascope.config import Config, load_config
from entrascope.http import (
    build_retry,
    build_session,
    error_payload,
    fan_out,
    get_json,
    header_value,
    request,
    session_scope,
    timeouts,
    user_agent,
)
from entrascope.models import ApiCallError

GRAPH = "https://graph.microsoft.com/v1.0/applications"


@pytest.fixture
def config() -> Config:
    """Return the repository configuration."""
    return load_config()


def test_retry_policy_comes_from_configuration(config: Config) -> None:
    """Every retry value is read from config/retry.yaml."""
    retry = build_retry(config)
    assert retry.total == config.retry.retry.total
    assert retry.backoff_factor == config.retry.retry.backoff_factor
    assert retry.respect_retry_after_header is True
    assert 429 in (retry.status_forcelist or [])


def test_session_carries_the_user_agent_and_pool(config: Config) -> None:
    """The session announces the running version and mounts the adapter."""
    with session_scope(config) as session:
        assert session.headers["User-Agent"] == user_agent(config)
        assert __version__ in session.headers["User-Agent"]
        adapter = session.get_adapter("https://example.invalid")
        assert adapter is session.get_adapter("http://example.invalid")


def test_timeouts_come_from_configuration(config: Config) -> None:
    """Connect and read timeouts are configured, not literal."""
    assert timeouts(config) == (
        config.retry.http.connect_timeout_seconds,
        config.retry.http.read_timeout_seconds,
    )


@responses.activate
def test_bearer_token_is_attached_per_request(config: Config) -> None:
    """The token provider is called per request rather than cached on the session."""
    calls: list[int] = []

    def provider() -> str:
        calls.append(1)
        return f"token-{len(calls)}"

    responses.add(responses.GET, GRAPH, json={"value": []}, status=200)
    responses.add(responses.GET, GRAPH, json={"value": []}, status=200)
    session = build_session(config, provider)
    get_json(session, GRAPH, config)
    get_json(session, GRAPH, config)
    sent = [call.request.headers["Authorization"] for call in responses.calls]
    assert sent == ["Bearer token-1", "Bearer token-2"]


@responses.activate
def test_graph_error_becomes_the_structured_error(config: Config) -> None:
    """A Graph failure carries its code, message and correlation id."""
    responses.add(
        responses.GET,
        GRAPH,
        json={
            "error": {
                "code": "Authorization_RequestDenied",
                "message": "Insufficient privileges.",
            }
        },
        status=403,
        headers={"client-request-id": "abc-123", "x-ms-request-id": "req-9"},
    )
    with pytest.raises(ApiCallError) as raised:
        get_json(build_session(config), GRAPH, config)
    error = raised.value.error
    assert error.status == 403
    assert error.code == "Authorization_RequestDenied"
    assert error.correlation_id == "abc-123"
    assert error.request_id == "req-9"
    assert "403" in error.summary()


@responses.activate
def test_token_endpoint_error_shape_is_recognised(config: Config) -> None:
    """The token endpoint reports error and error_description as strings."""
    url = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
    responses.add(
        responses.POST,
        url,
        json={
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided.",
        },
        status=401,
    )
    with pytest.raises(ApiCallError) as raised:
        request(build_session(config), "POST", url, config, source="token")
    assert raised.value.error.code == "invalid_client"
    assert "AADSTS7000215" in raised.value.error.message


@responses.activate
def test_non_json_error_body_is_kept(config: Config) -> None:
    """An HTML or plain text failure body is still reported."""
    responses.add(responses.GET, GRAPH, body="upstream exploded", status=502)
    with pytest.raises(ApiCallError) as raised:
        get_json(build_session(config), GRAPH, config)
    assert "upstream exploded" in raised.value.error.message


@responses.activate
def test_non_object_body_is_refused(config: Config) -> None:
    """A JSON array where an object was expected is an error, not a crash."""
    responses.add(responses.GET, GRAPH, json=[1, 2, 3], status=200)
    with pytest.raises(ApiCallError) as raised:
        get_json(build_session(config), GRAPH, config)
    assert raised.value.error.code == "UnexpectedBody"


def test_header_value_prefers_the_first_present() -> None:
    """Correlation headers are looked up in order."""
    assert header_value({"request-id": "b"}, ("client-request-id", "request-id")) == "b"
    assert header_value({}, ("a", "b")) == ""


def test_error_payload_handles_an_unexpected_shape() -> None:
    """A body that is neither of the known shapes still yields a message."""

    # framework contract: responses needs a real Response object to parse.
    response = requests.Response()
    response._content = b'{"unexpected": true}'
    response.status_code = 400
    code, message = error_payload(response)
    assert code == ""
    assert "unexpected" in message


@responses.activate
def test_request_logs_the_call(
    config: Config, caplog: pytest.LogCaptureFixture
) -> None:
    """Every call is logged with its method, status and elapsed time."""
    responses.add(responses.GET, GRAPH, json={"value": []}, status=200)
    with caplog.at_level("DEBUG", logger="entrascope.http"):
        get_json(build_session(config), GRAPH, config)
    assert any("returned 200" in record.message for record in caplog.records)


@responses.activate
def test_fan_out_preserves_order(config: Config) -> None:
    """Concurrent work returns results in the order of the input."""
    for index in range(12):
        responses.add(
            responses.GET, f"{GRAPH}/{index}", json={"id": str(index)}, status=200
        )

    def work(session: requests.Session, item: str) -> Any:
        return get_json(session, f"{GRAPH}/{item}", config)["id"]

    results = fan_out([str(index) for index in range(12)], work, config)
    assert list(results) == [str(index) for index in range(12)]


def test_fan_out_on_an_empty_sequence_does_nothing(config: Config) -> None:
    """No items means no sessions and no work."""

    def work(session: requests.Session, item: str) -> str:  # pragma: no cover
        raise AssertionError("should not be called")

    assert fan_out([], work, config) == ()
