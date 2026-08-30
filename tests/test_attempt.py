"""The sign in attempt: qualification, the flow, and what is torn down.

The parts that decide whether a sign in is safe are the ones tested hardest
here: the state that makes somebody else's redirect unusable, the proof key
that makes an intercepted code worthless, the listener that is bound to the
loopback address alone, and the fact that nothing is left behind afterwards.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import socket
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from entrascope.attempt import (
    Answer,
    answer_from_query,
    authorize_url,
    chosen_redirect,
    exchange,
    free_port,
    listen,
    page,
    parsed,
    platform_redirects,
    prepare,
    read_request_line,
    report,
    request_target,
    usable_redirects,
    verifier_and_challenge,
    why_it_cannot_be_attempted,
)
from entrascope.config import Config
from entrascope.http import build_session
from entrascope.models import (
    ApiCallError,
    ApplicationSummary,
    ConfigError,
    RedirectUris,
)

TOKEN = "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"


def application(
    *,
    public_client: tuple[str, ...] = (),
    web: tuple[str, ...] = (),
    spa: tuple[str, ...] = (),
    name: str = "Desktop client",
) -> ApplicationSummary:
    """Return a registration with the redirect URIs a test needs."""
    return ApplicationSummary(
        object_id="11111111-1111-1111-1111-111111111111",
        app_id="aaaaaaaa-1111-1111-1111-111111111111",
        display_name=name,
        application_type="native-or-mobile",
        sign_in_audience="AzureADMyOrg",
        audience_label="this tenant only",
        redirect_uris=RedirectUris(
            web=web, single_page=spa, public_client=public_client
        ),
        identifier_uris=(),
        requested_permissions=(),
        credentials=(),
        federated_credentials=(),
        owners=(),
        requested_access_token_version=2,
        created="",
    )


def test_a_loopback_redirect_qualifies_and_a_remote_one_does_not(
    config: Config,
) -> None:
    """A redirect that goes anywhere else cannot be caught by a listener here."""
    here = application(public_client=("http://127.0.0.1:47820/callback",))
    away = application(web=("https://app.example.invalid/callback",))
    assert usable_redirects(here, config)
    assert not usable_redirects(away, config)


def test_a_refused_port_does_not_qualify(config: Config) -> None:
    """Something else is almost always serving on 8080, and a redirect that
    reaches it is one this tool cannot see."""
    on_eighty_eighty = application(public_client=("http://127.0.0.1:8080/callback",))
    assert not usable_redirects(on_eighty_eighty, config)
    reason = why_it_cannot_be_attempted(on_eighty_eighty, config)
    assert "will not bind" in reason
    assert "8080" in reason


def test_an_application_with_nowhere_to_come_back_to_says_what_to_register(
    config: Config,
) -> None:
    """A refusal that names the command to fix it is an answer, not a refusal."""
    reason = why_it_cannot_be_attempted(application(), config)
    assert "no redirect URI on this machine" in reason
    assert "az ad app update" in reason
    assert "--public-client-redirect-uris" in reason
    # It says plainly that it will not make the change itself.
    assert "will not make it" in reason


def test_the_public_client_redirect_is_preferred_over_the_web_one(
    config: Config,
) -> None:
    """A public client needs no secret, so it is the one this tool can run alone."""
    both = application(
        public_client=("http://127.0.0.1:47821/callback",),
        web=("http://127.0.0.1:47820/callback",),
    )
    chosen = chosen_redirect(both, config)
    assert chosen.platform == "public_client"
    assert chosen.needs_secret() is False


def test_naming_a_redirect_uri_that_is_not_registered_lists_the_ones_that_are(
    config: Config,
) -> None:
    """A redirect URI has to match what is registered exactly."""
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    with pytest.raises(ConfigError, match="not a redirect URI"):
        chosen_redirect(one, config, "http://127.0.0.1:47899/elsewhere")


def test_the_platform_decides_whether_a_secret_is_needed(config: Config) -> None:
    """Entra requires one from a web redirect and refuses one from a public client."""
    web = application(web=("http://127.0.0.1:47820/callback",))
    assert chosen_redirect(web, config).needs_secret() is True


def test_a_redirect_uri_that_cannot_be_read_is_skipped_rather_than_raising() -> None:
    """A registration is somebody else's text, and some of it is nonsense."""
    assert parsed("http://127.0.0.1:notaport/callback", "web") is None
    assert parsed("not a uri at all", "web") is None
    assert parsed("http://127.0.0.1/callback", "web") is not None


def test_every_platform_is_reported_with_its_redirects() -> None:
    """The same address under a different platform is a different flow."""
    every = application(
        public_client=("http://127.0.0.1:1/a",),
        web=("http://127.0.0.1:2/b",),
        spa=("http://127.0.0.1:3/c",),
    )
    assert {item.platform for item in platform_redirects(every)} == {
        "public_client",
        "web",
        "spa",
    }


def test_the_proof_key_challenge_is_the_hash_of_the_verifier(config: Config) -> None:
    """S256 is what makes an intercepted code worthless, so the maths matters."""
    verifier, challenge = verifier_and_challenge(config)
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    assert challenge == expected
    # RFC 7636 allows 43 to 128 characters.
    assert 43 <= len(verifier) <= 128
    assert "=" not in verifier and "=" not in challenge


def test_two_attempts_never_share_a_state_or_a_verifier(config: Config) -> None:
    """A predictable state is no protection, and a shared verifier is none either."""
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    first = prepare(one, config, tenant_id="tenant-1")
    second = prepare(one, config, tenant_id="tenant-1")
    assert first.state != second.state
    assert first.verifier != second.verifier


def test_the_authorize_url_carries_everything_entra_needs(config: Config) -> None:
    """One wrong parameter here is a sign in that fails for no visible reason."""
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1", scopes=["User.Read"])
    parts = urlparse(prepared.authorize_url)
    query = {name: value[0] for name, value in parse_qs(parts.query).items()}
    assert parts.netloc == "login.microsoftonline.com"
    assert parts.path == "/tenant-1/oauth2/v2.0/authorize"
    assert query["client_id"] == one.app_id
    assert query["response_type"] == "code"
    assert query["redirect_uri"] == "http://127.0.0.1:47820/callback"
    assert query["scope"] == "User.Read"
    assert query["state"] == prepared.state
    assert query["code_challenge"] == prepared.challenge
    assert query["code_challenge_method"] == "S256"


def test_a_registration_with_no_port_gets_a_free_one(config: Config) -> None:
    """A native client registers without a port and chooses one at the time."""
    one = application(public_client=("http://127.0.0.1/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    first, last = config.oauth.listener.port_range
    assert first <= prepared.port <= last
    assert prepared.redirect_uri == f"http://127.0.0.1:{prepared.port}/callback"


def test_a_registration_with_a_port_is_used_exactly_as_registered(
    config: Config,
) -> None:
    """Entra compares the redirect URI byte for byte."""
    one = application(public_client=("http://127.0.0.1:47831/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    assert prepared.redirect_uri == "http://127.0.0.1:47831/callback"
    assert prepared.port == 47831


def test_preparing_without_a_tenant_says_so(config: Config) -> None:
    """There is no authority to sign in against without one."""
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    with pytest.raises(ConfigError, match="needs a tenant"):
        prepare(one, config, tenant_id="")


def test_a_refused_port_is_refused_even_when_asked_for(config: Config) -> None:
    """--port must not be a way round the refuse list."""
    one = application(public_client=("http://127.0.0.1/callback",))
    with pytest.raises(ConfigError, match="refuse list"):
        prepare(one, config, tenant_id="tenant-1", port=8080)


def test_free_port_stays_inside_the_configured_range(config: Config) -> None:
    """A port outside the range is one no redirect URI will have registered."""
    first, last = config.oauth.listener.port_range
    assert first <= free_port(config) <= last


def test_the_attempt_never_shows_the_verifier(config: Config) -> None:
    """It is what proves the exchange is ours, so it is a secret while it lives."""
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    assert prepared.verifier not in repr(prepared)
    assert "[redacted]" in repr(prepared)


def test_the_redirect_query_is_read_into_what_it_carries() -> None:
    """Both shapes: a code, and Entra's own refusal."""
    good = answer_from_query("code=abc&state=xyz")
    assert good.code == "abc"
    assert good.state == "xyz"
    assert good.failed() is False
    bad = answer_from_query("error=access_denied&error_description=AADSTS65004%3A+no")
    assert bad.error == "access_denied"
    assert "AADSTS65004" in bad.error_description
    assert bad.failed() is True
    # A redirect carrying neither is not a sign in either.
    assert Answer().failed() is True


def test_a_request_line_is_read_and_bounded() -> None:
    """A browser sends whatever it likes; only the first line is the redirect."""
    assert request_target(b"GET /callback?code=a HTTP/1.1") == "/callback?code=a"
    assert request_target(b"POST /callback HTTP/1.1") == ""
    assert request_target(b"nonsense") == ""


def test_the_page_shown_to_the_browser_escapes_what_it_carries() -> None:
    """The pages are configuration, and configuration is text somebody wrote."""
    rendered = page("<script>alert(1)</script>", "a & b").decode()
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "a &amp; b" in rendered
    assert "Content-Length:" in rendered


@responses.activate
def test_the_token_exchange_sends_the_verifier_and_no_secret(config: Config) -> None:
    """A public client that sends a secret is refused, and one that omits the
    verifier cannot prove the code is its own."""
    responses.add(responses.POST, TOKEN, json={"access_token": ""}, status=200)
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    exchange(build_session(config), config, prepared, "the-code")
    sent = parse_qs(responses.calls[0].request.body or "")
    assert sent["code"] == ["the-code"]
    assert sent["code_verifier"] == [prepared.verifier]
    assert sent["grant_type"] == ["authorization_code"]
    assert sent["redirect_uri"] == ["http://127.0.0.1:47820/callback"]
    assert "client_secret" not in sent


@responses.activate
def test_a_supplied_secret_is_sent_and_nothing_else_changes(config: Config) -> None:
    """A web platform redirect needs one, and only then is one sent."""
    responses.add(responses.POST, TOKEN, json={"access_token": ""}, status=200)
    one = application(web=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    exchange(build_session(config), config, prepared, "the-code", "the-secret")
    sent = parse_qs(responses.calls[0].request.body or "")
    assert sent["client_secret"] == ["the-secret"]
    assert sent["code_verifier"] == [prepared.verifier]


@responses.activate
def test_a_refused_exchange_becomes_the_one_structured_error(config: Config) -> None:
    """The token endpoint answers with a code this tool already explains."""
    responses.add(
        responses.POST,
        TOKEN,
        json={
            "error": "invalid_grant",
            "error_description": "AADSTS54005: code already redeemed.",
        },
        status=400,
    )
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    with pytest.raises(ApiCallError) as raised:
        exchange(build_session(config), config, prepared, "spent")
    assert raised.value.error.code == "invalid_grant"
    assert "AADSTS54005" in raised.value.error.message


def test_the_report_says_what_was_granted_against_what_was_asked(
    config: Config,
) -> None:
    """A scope asked for and not granted is a call that will be refused later."""
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(
        one, config, tenant_id="tenant-1", scopes=["User.Read", "Mail.Read"]
    )
    written = report(
        prepared,
        {"token_type": "Bearer", "expires_in": 3599, "scope": "User.Read"},
        config,
        confidential=False,
    )
    assert written["scopes"]["granted"] == ["User.Read"]
    assert written["scopes"]["not_granted"] == ["Mail.Read"]
    assert "Mail.Read" in written["note"]
    assert "refused" in written["note"]
    assert written["flow"]["client"] == "public"
    assert written["flow"]["proof_key"] == "S256"
    assert written["token"]["refresh_token_issued"] is False


def test_the_report_is_quiet_when_everything_asked_for_was_granted(
    config: Config,
) -> None:
    """Nothing to say is worth saying plainly."""
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1", scopes=["User.Read"])
    written = report(
        prepared,
        {"scope": "User.Read", "refresh_token": "r"},
        config,
        confidential=True,
    )
    assert written["scopes"]["not_granted"] == []
    assert "Every scope asked for was granted" in written["note"]
    assert written["flow"]["client"] == "confidential"
    assert written["token"]["refresh_token_issued"] is True


def redirect_to(port: int, path: str, query: str) -> None:
    """Send one request to the listener, the way a browser would."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(f"GET {path}?{query} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        client.recv(2048)


def test_the_listener_catches_one_redirect_and_closes(config: Config) -> None:
    """The whole flow through the socket, and nothing left listening after it."""
    one = application(public_client=("http://127.0.0.1/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    caught: list[Any] = []

    def wait() -> None:
        caught.append(listen(prepared, config))

    listener = threading.Thread(target=wait)
    listener.start()
    try:
        wait_until_listening(prepared.port)
        redirect_to(prepared.port, "/callback", f"code=abc&state={prepared.state}")
    finally:
        listener.join(timeout=15)
    assert caught and caught[0].code == "abc"
    assert caught[0].state == prepared.state
    # Nothing is left holding the port, which is what makes running it twice work.
    assert port_is_free(prepared.port)


def test_the_listener_ignores_anything_that_is_not_the_redirect(
    config: Config,
) -> None:
    """A browser asks for a favicon on the same address before anything else."""
    one = application(public_client=("http://127.0.0.1/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    caught: list[Any] = []

    def wait() -> None:
        caught.append(listen(prepared, config))

    listener = threading.Thread(target=wait)
    listener.start()
    try:
        wait_until_listening(prepared.port)
        redirect_to(prepared.port, "/favicon.ico", "")
        redirect_to(prepared.port, "/callback", f"code=abc&state={prepared.state}")
    finally:
        listener.join(timeout=15)
    assert caught and caught[0].code == "abc"


def test_the_listener_gives_up_and_closes_rather_than_waiting_forever(
    config: Config,
) -> None:
    """A forgotten browser window must not hold a socket open all afternoon."""
    one = application(public_client=("http://127.0.0.1/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    impatient = config.model_copy(
        update={
            "oauth": config.oauth.model_copy(
                update={
                    "listener": config.oauth.listener.model_copy(
                        update={"timeout_seconds": 0.2}
                    )
                }
            )
        }
    )
    with pytest.raises(ApiCallError) as raised:
        listen(prepared, impatient)
    assert raised.value.error.code == "SignInTimedOut"
    assert "closed" in raised.value.error.message
    assert port_is_free(prepared.port)


def test_the_listener_binds_the_loopback_address_and_nothing_else(
    config: Config,
) -> None:
    """Nothing off this machine may reach it, even for the second it is up."""
    assert config.oauth.listener.bind_host == "127.0.0.1"
    one = application(public_client=("http://127.0.0.1/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    listener = threading.Thread(target=lambda: guarded(prepared, config))
    listener.start()
    try:
        wait_until_listening(prepared.port)
        # The port is open on the loopback address and closed on every other
        # address this machine answers to.
        assert not reachable(host_address(), prepared.port)
    finally:
        redirect_to(prepared.port, "/callback", f"code=a&state={prepared.state}")
        listener.join(timeout=15)


def guarded(prepared: Any, config: Config) -> None:
    """Run the listener, swallowing the timeout a test may cause."""
    with contextlib.suppress(ApiCallError):
        listen(prepared, config)


def host_address() -> str:
    """Return an address this machine answers to that is not the loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))
        return str(probe.getsockname()[0])


def reachable(host: str, port: int) -> bool:
    """Return whether something is listening at an address."""
    if host.startswith("127."):
        return True
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex((host, port)) == 0


def wait_until_listening(port: int, tries: int = 200) -> None:
    """Block until the listener is up, rather than guessing at a delay."""
    for _ in range(tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.05)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
    raise AssertionError(f"nothing came up on {port}")


def port_is_free(port: int) -> bool:
    """Return whether the port can be bound again, which means it was released."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def test_reading_a_request_line_stops_at_the_limit() -> None:
    """A line longer than a redirect could be is not a redirect."""
    listener, client = socket.socketpair()
    with listener, client:
        client.sendall(b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\n")
        assert len(read_request_line(listener, 512)) <= 512


def test_authorize_url_omits_the_prompt_when_configuration_clears_it(
    config: Config,
) -> None:
    """A site that wants an existing session to answer can say so."""
    quiet = config.oauth.authorize.model_copy(update={"prompt": ""})
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    built = authorize_url(
        config.model_copy(
            update={"oauth": config.oauth.model_copy(update={"authorize": quiet})}
        ),
        one,
        "tenant-1",
        "http://127.0.0.1:47820/callback",
        "state",
        "challenge",
        ["User.Read"],
    )
    assert "prompt=" not in built


def test_a_refusal_on_the_redirect_carries_the_explanation(config: Config) -> None:
    """Entra sends the reason to the redirect, so this is where it can be read."""
    from entrascope.attempt import refusal

    error = refusal(
        Answer(
            error="access_denied",
            error_description="AADSTS65004: The user declined to consent.",
        ),
        config,
    ).error
    assert error.code == "access_denied"
    assert "AADSTS65004" in error.message
    assert error.source == "attempt"


def test_a_refusal_with_no_description_still_says_something(config: Config) -> None:
    """A redirect carrying an error and nothing else is still an answer."""
    from entrascope.attempt import refusal

    error = refusal(Answer(error="server_error"), config).error
    assert "no description given" in error.message


def test_a_refusal_that_names_no_error_is_still_one(config: Config) -> None:
    """A redirect with neither a code nor an error did not complete either."""
    from entrascope.attempt import refusal

    assert refusal(Answer(), config).error.code == "AuthorizationFailed"


def test_the_browser_is_not_opened_when_configuration_says_not_to(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A machine with no browser is somebody's real situation."""
    from entrascope.attempt import open_browser

    opened: list[str] = []
    monkeypatch.setattr(
        "entrascope.attempt.webbrowser.open", lambda url: opened.append(url) or True
    )
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")

    quiet = config.model_copy(
        update={
            "oauth": config.oauth.model_copy(
                update={
                    "browser": config.oauth.browser.model_copy(
                        update={"open_automatically": False}
                    )
                }
            )
        }
    )
    assert open_browser(prepared, quiet) is False
    assert not opened
    assert open_browser(prepared, config) is True
    assert opened == [prepared.authorize_url]


def test_a_browser_that_cannot_be_opened_is_not_a_failure(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The address is printed instead, and the flow still works."""
    from entrascope.attempt import open_browser

    def refuse(url: str) -> bool:
        raise OSError("no display")

    monkeypatch.setattr("entrascope.attempt.webbrowser.open", refuse)
    one = application(public_client=("http://127.0.0.1:47820/callback",))
    prepared = prepare(one, config, tenant_id="tenant-1")
    assert open_browser(prepared, config) is False
