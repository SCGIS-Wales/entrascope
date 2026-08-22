"""Transport tests: session construction, retry, logging and error shaping."""

from __future__ import annotations

from pathlib import Path
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


def test_proxies_are_read_from_the_environment(config: Config) -> None:
    """Conventional proxy variables are honoured, https winning over http."""
    from entrascope.http import resolve_proxies

    proxies = resolve_proxies(
        config.retry.network,
        {
            "HTTPS_PROXY": "http://proxy.example.invalid:8080",
            "HTTP_PROXY": "http://proxy.example.invalid:3128",
            "NO_PROXY": "localhost,.example.invalid",
        },
    )
    assert proxies["https"] == "http://proxy.example.invalid:8080"
    assert proxies["http"] == "http://proxy.example.invalid:3128"
    assert proxies["no_proxy"] == "localhost,.example.invalid"


def test_lowercase_proxy_variables_are_honoured(config: Config) -> None:
    """The lowercase spelling is as common as the uppercase one."""
    from entrascope.http import resolve_proxies

    proxies = resolve_proxies(
        config.retry.network, {"https_proxy": "http://proxy.example.invalid:8080"}
    )
    assert proxies["https"].endswith(":8080")


def test_no_proxy_configured_is_not_an_error(config: Config) -> None:
    """An environment with no proxy yields no proxy settings."""
    from entrascope.http import resolve_proxies

    assert resolve_proxies(config.retry.network, {}) == {}


def test_ca_bundle_file_is_trusted(tmp_path: Path, config: Config) -> None:
    """A certificate authority bundle named in the environment is used."""
    from entrascope.http import resolve_ca_trust

    bundle = tmp_path / "corporate-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    verify, origin = resolve_ca_trust(
        config.retry.network, {"SSL_CERT_FILE": str(bundle)}
    )
    assert verify == str(bundle)
    assert origin == "SSL_CERT_FILE"


def test_ca_bundle_variables_are_tried_in_order(tmp_path: Path, config: Config) -> None:
    """The first variable that names an existing file wins."""
    from entrascope.http import resolve_ca_trust

    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    verify, origin = resolve_ca_trust(
        config.retry.network,
        {
            "ENTRASCOPE_CA_BUNDLE": str(bundle),
            "SSL_CERT_FILE": str(tmp_path / "absent"),
        },
    )
    assert origin == "ENTRASCOPE_CA_BUNDLE"
    assert verify == str(bundle)


def test_a_ca_directory_is_used_when_no_bundle_is_set(
    tmp_path: Path, config: Config
) -> None:
    """The OpenSSL directory convention is honoured when no bundle file is named."""
    from entrascope.http import resolve_ca_trust

    directory = tmp_path / "certs"
    directory.mkdir()
    verify, origin = resolve_ca_trust(
        config.retry.network, {"SSL_CERT_DIR": str(directory)}
    )
    assert verify == str(directory)
    assert origin == "SSL_CERT_DIR"


def test_a_missing_ca_path_falls_back_to_the_default_bundle(config: Config) -> None:
    """A variable pointing at nothing does not silently disable verification."""
    from entrascope.http import resolve_ca_trust

    verify, origin = resolve_ca_trust(
        config.retry.network, {"SSL_CERT_FILE": "/no/such/bundle.pem"}
    )
    assert verify is True
    assert "default" in origin


def test_verification_is_never_disabled_by_a_missing_variable(config: Config) -> None:
    """With nothing configured, verification stays on."""
    from entrascope.http import resolve_ca_trust

    assert resolve_ca_trust(config.retry.network, {})[0] is True


def test_verification_can_be_disabled_only_in_configuration(config: Config) -> None:
    """Turning verification off is a deliberate configuration change."""
    from entrascope.http import resolve_ca_trust

    settings = config.retry.network.model_copy(update={"verify_tls": False})
    verify, origin = resolve_ca_trust(settings, {})
    assert verify is False
    assert "disabled" in origin


def test_the_session_applies_the_proxy_and_the_certificate_authority(
    tmp_path: Path, config: Config
) -> None:
    """Both settings reach the session that every call goes through."""
    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    environ = {
        "HTTPS_PROXY": "http://proxy.example.invalid:8080",
        "REQUESTS_CA_BUNDLE": str(bundle),
    }
    session = build_session(config, environ=environ)
    assert session.verify == str(bundle)
    assert session.proxies["https"] == "http://proxy.example.invalid:8080"
    assert session.trust_env is True


def test_network_trust_is_describable(tmp_path: Path, config: Config) -> None:
    """The doctor report can state exactly what is in force."""
    from entrascope.http import network_trust

    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    trust = network_trust(
        config,
        {
            "HTTP_PROXY": "http://proxy.example.invalid:3128",
            "SSL_CERT_FILE": str(bundle),
        },
    )
    assert trust.verify_enabled
    assert "proxy.example.invalid" in trust.summary()
    assert str(bundle) in trust.summary()
    assert network_trust(config, {}).summary().endswith("default certificate bundle")


def test_the_azure_clients_take_the_same_verification_setting(
    tmp_path: Path, config: Config
) -> None:
    """azure-core based clients trust the same certificate authority we do."""
    from entrascope.http import verify_setting

    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    assert verify_setting(config, {"SSL_CERT_FILE": str(bundle)}) == str(bundle)
    assert verify_setting(config, {}) is True


def test_an_interrupted_fan_out_abandons_its_queue(config: Config) -> None:
    """Control C means stop, not finish everything already queued.

    The pool is driven by hand rather than through its context manager, because
    that manager drains the queue on the way out.
    """
    started: list[int] = []

    def work(session: requests.Session, item: int) -> int:
        started.append(item)
        if item == 0:
            raise KeyboardInterrupt
        return item

    single = config.model_copy(
        update={
            "retry": config.retry.model_copy(
                update={
                    "concurrency": config.retry.concurrency.model_copy(
                        update={"max_workers": 1}
                    )
                }
            )
        }
    )
    with pytest.raises(KeyboardInterrupt):
        fan_out(list(range(50)), work, single)
    assert len(started) < 50
