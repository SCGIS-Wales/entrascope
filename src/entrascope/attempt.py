"""One authorization code sign in, run for real.

Everything else in this tool reads what a tenant has recorded. This runs the
flow, because a registration that looks correct and a sign in that works are
different claims, and only one of them is worth anything to somebody whose
users cannot get in.

The shape is the one RFC 8252 specifies for a native application, which is what
a command line tool is: an external browser rather than an embedded one, a
loopback redirect, a high entropy state, and proof key for code exchange so
that a code intercepted on the loopback interface cannot be spent. No secret is
needed for any of that. One may be supplied to exercise a confidential client's
exchange as well, and it is never written down, never logged and never kept.

Nothing here changes the directory. The listener is the only thing created, it
is bound to the loopback address alone, it answers exactly one redirect, and it
is closed on every path out of here including an interrupt.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import time
import webbrowser
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple
from urllib.parse import parse_qs, urlencode, urlparse

from entrascope.config import Config
from entrascope.discovery import text
from entrascope.http import Session, request
from entrascope.logger import get_logger
from entrascope.models import ApiCallError, ApiError, ApplicationSummary, ConfigError
from entrascope.sanitise import bounded, one_line

log = get_logger(__name__)

#: What the loopback listener will read of a request before giving up on it.
#: A redirect is one line; anything longer is not the thing being waited for.
REQUEST_LINE_TERMINATOR = b"\r\n"

#: The scheme a loopback redirect URI uses. Entra permits plain HTTP for the
#: loopback address and for nothing else, which is what makes this work without
#: a certificate.
LOOPBACK_SCHEME = "http"

#: The hosts Entra treats as the loopback interface.
LOOPBACK_HOSTS = ("127.0.0.1", "localhost")


class Redirect(NamedTuple):
    """One redirect URI an application has registered, taken apart.

    A redirect URI has to match what is registered exactly, so it is used as
    registered rather than rebuilt, except for the port: a native client
    registers one without a port and chooses a free one at the time, which is
    the behaviour RFC 8252 describes and Entra permits.
    """

    uri: str
    #: web, spa or public_client, as the registration files it. What the
    #: platform is decides whether a secret is needed.
    platform: str
    host: str
    #: None when the registration named no port, in which case one is chosen.
    port: int | None
    path: str

    def loopback(self) -> bool:
        """Return whether this redirect comes back to this machine."""
        return self.host in LOOPBACK_HOSTS

    def needs_secret(self) -> bool:
        """Return whether the token exchange will be refused without a secret.

        Entra requires a secret from the web platform and refuses one from the
        others. Which platform a redirect URI is registered under is therefore
        the whole of the answer.
        """
        return self.platform == "web"


class Attempt(NamedTuple):
    """What was set up before the browser was opened.

    Held together so that the verifier used to build the challenge is the one
    sent to the token endpoint, and the state sent is the one checked on the
    way back. Two values that must agree are one object.
    """

    application: ApplicationSummary
    tenant_id: str
    redirect: Redirect
    redirect_uri: str
    port: int
    state: str
    verifier: str
    challenge: str
    scopes: tuple[str, ...]
    authorize_url: str

    def __repr__(self) -> str:
        """Return a representation that cannot leak the verifier."""
        return (
            f"Attempt(application={self.application.app_id!r}, "
            f"redirect_uri={self.redirect_uri!r}, verifier='[redacted]')"
        )


def platform_redirects(application: ApplicationSummary) -> tuple[Redirect, ...]:
    """Return every redirect URI the application has, with its platform.

    The platform is not a detail. Entra requires a secret from a web platform
    redirect and refuses one from a public client redirect, so the same address
    registered under a different platform is a different flow.
    """
    uris = application.redirect_uris
    found: list[Redirect] = []
    for platform, values in (
        ("public_client", uris.public_client),
        ("web", uris.web),
        ("spa", uris.single_page),
    ):
        for value in values:
            redirect = parsed(value, platform)
            if redirect is not None:
                found.append(redirect)
    return tuple(found)


def parsed(uri: str, platform: str) -> Redirect | None:
    """Take one redirect URI apart, or return None when it is unusable."""
    try:
        parts = urlparse(uri)
    except ValueError:
        log.debug("could not read the redirect URI %s", one_line(uri))
        return None
    if not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        # A port that is not a number. Registered by hand, and unusable.
        return None
    return Redirect(
        uri=uri,
        platform=platform,
        host=parts.hostname,
        port=port,
        path=parts.path or "/",
    )


def usable_redirects(
    application: ApplicationSummary, config: Config
) -> tuple[Redirect, ...]:
    """Return the redirect URIs this tool can actually receive on.

    A redirect that goes anywhere but this machine cannot be caught by a
    listener on this machine, and a port that something else is expected to be
    serving is refused rather than fought over.
    """
    refused = set(config.oauth.listener.refuse_ports)
    return tuple(
        item
        for item in platform_redirects(application)
        if item.loopback() and item.port not in refused
    )


def why_it_cannot_be_attempted(application: ApplicationSummary, config: Config) -> str:
    """Say why an application cannot be signed into here, or nothing.

    Naming the redirect URI to register, rather than saying it is unsuitable,
    is the difference between a refusal and an answer.
    """
    if usable_redirects(application, config):
        return ""
    listener = config.oauth.listener
    wanted = (
        f"{LOOPBACK_SCHEME}://{listener.host}:{listener.port_range[0]}{listener.path}"
    )
    registered = [item.uri for item in platform_redirects(application)]
    refused = [
        item.uri
        for item in platform_redirects(application)
        if item.loopback() and item.port in set(listener.refuse_ports)
    ]
    reason = (
        f"{application.display_name} has no redirect URI on this machine, so "
        "there is nowhere for Entra to send the code back to."
    )
    if refused:
        reason = (
            f"{application.display_name} redirects to this machine only on a "
            f"port entrascope will not bind: {', '.join(refused)}. Something "
            "else is almost certainly serving there, and a redirect that "
            "reaches it is one this tool cannot see."
        )
    return (
        f"{reason}\n"
        f"  Registered: {', '.join(registered) or 'nothing'}\n"
        f"  Add a mobile and desktop platform redirect of {wanted}, which needs "
        "no secret:\n"
        f"    az ad app update --id {application.app_id} "
        f"--public-client-redirect-uris {wanted}\n"
        "  Adding one is a change to the registration, so entrascope will not "
        "make it. The command above is the whole of it."
    )


def free_port(config: Config) -> int:
    """Return a port in the configured range that nothing is listening on.

    Used when the registered redirect URI names no port, which is how a native
    client registers one. Bound and released immediately, so there is a moment
    in which something else could take it; the alternative is guessing, and the
    listener reports plainly if the bind then fails.
    """
    listener = config.oauth.listener
    first, last = listener.port_range
    refused = set(listener.refuse_ports)
    for port in range(first, last + 1):
        if port in refused:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((listener.bind_host, port))
            except OSError:
                continue
            return port
    raise ConfigError(
        f"No port between {first} and {last} is free, so there is nowhere for "
        "the redirect to land. Close whatever is using them, or widen "
        "listener.port_range in config/oauth.yaml."
    )


def verifier_and_challenge(config: Config) -> tuple[str, str]:
    """Return a PKCE verifier and the challenge derived from it.

    The verifier is kept and sent to the token endpoint; the challenge is what
    goes to the authorize endpoint. A code intercepted on the loopback
    interface is worthless without the verifier, which is the whole point.
    """
    settings = config.oauth.pkce
    verifier = base64url(secrets.token_bytes(settings.verifier_bytes))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64url(digest)


def base64url(raw: bytes) -> str:
    """Return base64url without padding, which is what the specification wants."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def chosen_redirect(
    application: ApplicationSummary, config: Config, wanted: str = ""
) -> Redirect:
    """Return the redirect URI to use, preferring one that needs no secret.

    Where an application registers several, a public client redirect is chosen
    over a web one, because the public client flow needs no secret and is the
    one this tool can run on its own.
    """
    usable = usable_redirects(application, config)
    if not usable:
        raise ConfigError(why_it_cannot_be_attempted(application, config))
    if wanted:
        found = next((item for item in usable if item.uri == wanted), None)
        if found is None:
            listed = "\n    ".join(item.uri for item in usable)
            raise ConfigError(
                f"{wanted} is not a redirect URI this application can be "
                f"signed into on. The ones it can:\n    {listed}"
            )
        return found
    return min(usable, key=lambda item: (item.needs_secret(), item.uri))


def prepare(
    application: ApplicationSummary,
    config: Config,
    *,
    tenant_id: str,
    scopes: Sequence[str] = (),
    redirect_uri: str = "",
    port: int | None = None,
) -> Attempt:
    """Work out everything the browser needs, without contacting anything.

    Separated from running the flow so that it can be checked on its own: the
    authorize URL this builds is the whole of what the sign in depends on, and
    a test can read it without a tenant, a browser or a socket.
    """
    if not tenant_id:
        raise ConfigError(
            "The sign in attempt needs a tenant, and the identity in use does "
            "not name one. Pass --tenant with the tenant id or domain."
        )
    redirect = chosen_redirect(application, config, redirect_uri)
    listener = config.oauth.listener
    resolved_port = port or redirect.port or free_port(config)
    if resolved_port in set(listener.refuse_ports):
        raise ConfigError(
            f"Port {resolved_port} is on the refuse list in config/oauth.yaml, "
            "because something else is almost certainly serving there."
        )
    # Rebuilt only when the registration named no port, which is how a native
    # client registers one. Otherwise it is sent exactly as registered, because
    # Entra compares it byte for byte.
    address = (
        redirect.uri
        if redirect.port is not None
        else f"{LOOPBACK_SCHEME}://{redirect.host}:{resolved_port}{redirect.path}"
    )
    verifier, challenge = verifier_and_challenge(config)
    state = base64url(secrets.token_bytes(config.oauth.pkce.state_bytes))
    wanted_scopes = tuple(scopes) or tuple(config.oauth.authorize.default_scopes)
    return Attempt(
        application=application,
        tenant_id=tenant_id,
        redirect=redirect,
        redirect_uri=address,
        port=resolved_port,
        state=state,
        verifier=verifier,
        challenge=challenge,
        scopes=wanted_scopes,
        authorize_url=authorize_url(
            config, application, tenant_id, address, state, challenge, wanted_scopes
        ),
    )


def authorize_url(
    config: Config,
    application: ApplicationSummary,
    tenant_id: str,
    redirect_uri: str,
    state: str,
    challenge: str,
    scopes: Sequence[str],
) -> str:
    """Build the address the browser is sent to."""
    settings = config.oauth.authorize
    endpoint = config.endpoints.authority.v2.authorize_endpoint_template.format(
        tenant_id=tenant_id
    )
    parameters = {
        "client_id": application.app_id,
        "response_type": settings.response_type,
        "redirect_uri": redirect_uri,
        "response_mode": settings.response_mode,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": config.oauth.pkce.method,
    }
    if settings.prompt:
        parameters["prompt"] = settings.prompt
    return f"{endpoint}?{urlencode(parameters)}"


class Answer(NamedTuple):
    """What came back to the redirect URI."""

    code: str = ""
    state: str = ""
    error: str = ""
    error_description: str = ""

    def failed(self) -> bool:
        """Return whether Entra answered with an error rather than a code."""
        return bool(self.error) or not self.code


def answer_from_query(query: str) -> Answer:
    """Read the redirect's query string into what it carries."""
    values = parse_qs(query, keep_blank_values=True)

    def one(name: str) -> str:
        found = values.get(name) or [""]
        return text(found[0])

    return Answer(
        code=one("code"),
        state=one("state"),
        error=one("error"),
        error_description=one("error_description"),
    )


def page(title: str, body: str) -> bytes:
    """Return the whole HTTP response the browser is shown.

    Self contained by necessity: the socket closes the moment this is written,
    so a page that fetched anything would fetch it from a server that has gone.
    """
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{escaped(title)}</title></head>"
        f"<body style='font-family:system-ui;margin:4rem auto;max-width:34rem'>"
        f"<h1>{escaped(title)}</h1><p>{escaped(body.strip())}</p></body></html>"
    )
    encoded = html.encode("utf-8")
    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(encoded)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    )
    return headers.encode("ascii") + encoded


def escaped(value: str) -> str:
    """Escape text for HTML. The pages are configuration, and configuration is text."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def listen(attempt: Attempt, config: Config) -> Answer:
    """Wait for the one redirect, and answer the browser.

    Bound to the loopback address alone, so nothing off this machine can reach
    it even for the moment it is up. Anything that is not the redirect being
    waited for is answered and ignored rather than accepted, because a browser
    with several tabs open will ask for a favicon before anything else.

    The socket is closed on every path out of here, including a timeout and an
    interrupt.
    """
    listener = config.oauth.listener
    pages = config.oauth.pages
    deadline = time.monotonic() + listener.timeout_seconds
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((listener.bind_host, attempt.port))
        except OSError as error:
            raise ConfigError(
                f"Could not listen on {listener.bind_host}:{attempt.port}, so "
                f"the redirect has nowhere to land: {error}\n"
                "  Something else is using the port. Close it, or pass --port "
                "with one that is free and registered on the application."
            ) from error
        server.listen(1)
        log.info(
            "listening for the redirect on %s:%s%s",
            listener.bind_host,
            attempt.port,
            listener.path,
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ApiCallError(
                    ApiError(
                        status=0,
                        code="SignInTimedOut",
                        message=(
                            f"No redirect arrived within "
                            f"{listener.timeout_seconds:.0f} seconds. The sign "
                            "in was not completed, or the browser was sent "
                            "somewhere else. The listener has been closed."
                        ),
                        source="attempt",
                    )
                )
            server.settimeout(remaining)
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            with connection:
                answer = served(connection, attempt, config, pages)
            if answer is not None:
                return answer


def served(
    connection: socket.socket,
    attempt: Attempt,
    config: Config,
    pages: Any,
) -> Answer | None:
    """Read one request, answer it, and return what it carried if it was the one.

    A browser asks for a favicon and anything else it fancies on the same
    address. Only the path the redirect was sent to is the redirect.
    """
    listener = config.oauth.listener
    connection.settimeout(listener.read_timeout_seconds)
    try:
        line = read_request_line(connection, listener.max_request_bytes)
    except (TimeoutError, OSError) as error:
        log.debug("a connection said nothing usable: %s", error)
        return None
    target = request_target(line)
    if not target:
        connection.sendall(page(pages.ignored_title, pages.ignored_body))
        return None
    parts = urlparse(target)
    if parts.path != urlparse(attempt.redirect_uri).path:
        log.debug("ignored a request for %s", one_line(parts.path))
        connection.sendall(page(pages.ignored_title, pages.ignored_body))
        return None
    answer = answer_from_query(parts.query)
    if answer.failed():
        connection.sendall(page(pages.failure_title, pages.failure_body))
    else:
        connection.sendall(page(pages.success_title, pages.success_body))
    return answer


def read_request_line(connection: socket.socket, limit: int) -> bytes:
    """Read the first line of an HTTP request, and no more of it.

    The redirect carries everything on the request line, so the headers and
    whatever follows them are of no interest and are not read. A line longer
    than the limit is not a redirect.
    """
    buffer = b""
    while REQUEST_LINE_TERMINATOR not in buffer and len(buffer) < limit:
        received = connection.recv(min(1024, limit - len(buffer)))
        if not received:
            break
        buffer += received
    return buffer.split(REQUEST_LINE_TERMINATOR, 1)[0]


def request_target(line: bytes) -> str:
    """Return the target of a request line, or nothing when it is not one."""
    parts = line.decode("latin-1", errors="replace").split(" ")
    if len(parts) < 2 or parts[0] != "GET":
        return ""
    return bounded(parts[1], 8192)


def exchange(
    session: Session,
    config: Config,
    attempt: Attempt,
    code: str,
    secret: str = "",
) -> dict[str, Any]:
    """Swap the authorisation code for tokens.

    The verifier proves this is the same client that asked for the code, which
    is what makes an intercepted code useless. A secret is sent only when one
    was supplied, because Entra refuses one from a public client and requires
    one from a web client, and the platform decides which this is.
    """
    endpoint = config.endpoints.authority.v2.token_endpoint_template.format(
        tenant_id=attempt.tenant_id
    )
    form = {
        "client_id": attempt.application.app_id,
        "grant_type": config.oauth.token.grant_type,
        "code": code,
        "redirect_uri": attempt.redirect_uri,
        "code_verifier": attempt.verifier,
        "scope": " ".join(attempt.scopes),
    }
    if secret:
        form["client_secret"] = secret
    response = request(
        session, "POST", endpoint, config, form_body=form, source="token"
    )
    body = response.json()
    return dict(body) if isinstance(body, Mapping) else {}


def report(
    attempt: Attempt,
    tokens: Mapping[str, Any],
    config: Config,
    *,
    confidential: bool,
) -> dict[str, Any]:
    """Say what the sign in actually produced.

    What a token carries is the answer, and it is rarely what the registration
    implies. The scopes granted are what the person consented to rather than
    what was asked for, and the difference between the two is the finding.
    """
    from entrascope.capabilities import claim_values, decode_claims

    access = text(tokens.get("access_token"))
    claims = decode_claims(access) if access else {}
    granted = claim_values(claims, "scp") or tuple(text(tokens.get("scope")).split())
    asked = tuple(attempt.scopes)
    return {
        "result": "signed in",
        "application": {
            "display_name": attempt.application.display_name,
            "application_id": attempt.application.app_id,
            "tenant_id": attempt.tenant_id,
        },
        "flow": {
            "grant_type": config.oauth.token.grant_type,
            "client": "confidential" if confidential else "public",
            "proof_key": config.oauth.pkce.method,
            "redirect_uri": attempt.redirect_uri,
            "platform": attempt.redirect.platform,
        },
        "token": {
            "type": text(tokens.get("token_type")),
            "expires_in_seconds": tokens.get("expires_in"),
            "refresh_token_issued": bool(tokens.get("refresh_token")),
            "id_token_issued": bool(tokens.get("id_token")),
        },
        "identity": {
            name: text(claims.get(name))
            for name in ("upn", "preferred_username", "name", "oid", "tid")
            if claims.get(name)
        },
        "scopes": {
            "requested": list(asked),
            "granted": list(granted),
            # What was asked for and not granted is the whole of why a call
            # made with this token would be refused.
            "not_granted": [item for item in asked if item not in set(granted)],
        },
        "roles": list(claim_values(claims, "roles")),
        "audience": text(claims.get("aud")),
        "issuer": text(claims.get("iss")),
        "note": consent_note(asked, granted),
    }


def consent_note(asked: Sequence[str], granted: Sequence[str]) -> str:
    """Say what the difference between asked and granted means."""
    missing = [item for item in asked if item not in set(granted)]
    if not missing:
        return (
            "Every scope asked for was granted, so a call needing one of them "
            "will not be refused for want of consent."
        )
    return (
        f"{len(missing)} scope(s) were asked for and not granted: "
        f"{', '.join(missing)}. A call needing one of them is refused, and the "
        "sign in still succeeds, which is why this reads as working until "
        "something fails. Record consent, or ask for less."
    )


def refusal(answer: Answer, config: Config) -> ApiCallError:
    """Turn an error on the redirect into the one error every surface renders.

    Entra sends the reason to the redirect URI rather than to the token
    endpoint, so this is the only place it can be read, and it carries an
    AADSTS code that this tool already knows how to explain.
    """
    from entrascope.errors import explain

    description = one_line(answer.error_description) or "no description given"
    explanation = explain(description, config)
    message = f"{answer.error or 'the sign in did not complete'}: {description}"
    if explanation.known:
        message = f"{message}\n  {explanation.code}: {explanation.meaning}"
    return ApiCallError(
        ApiError(
            status=0,
            code=answer.error or "AuthorizationFailed",
            message=message,
            source="attempt",
        )
    )


def open_browser(attempt: Attempt, config: Config) -> bool:
    """Open the sign in page, reporting whether it could be opened.

    RFC 8252 requires an external user agent rather than an embedded one, and
    the platform's default handler is exactly that: the browser somebody is
    already signed into. Where there is no browser to open, the address is
    printed instead and the flow still works.
    """
    if not config.oauth.browser.open_automatically:
        return False
    try:
        opened = webbrowser.open(attempt.authorize_url)
    except OSError as error:
        log.debug("could not open a browser: %s", error)
        return False
    if not opened:
        log.debug("no browser was available to open")
    return bool(opened)
