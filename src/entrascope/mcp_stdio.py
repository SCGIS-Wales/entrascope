"""The local MCP server, over stdio.

stdio has no OAuth, so credentials come from the environment or the credential
file exactly as they do for the command line. The server runs with the
privileges of whoever launched it, so it reads and never writes, validates its
input, and lets no secret into a tool result.
"""

from __future__ import annotations

from pathlib import Path

from fastmcp import FastMCP

from entrascope.config import Config, load_config
from entrascope.logger import configure_logging, get_logger
from entrascope.mcp_tools import (
    INSTRUCTIONS,
    SERVER_NAME,
    credential_factory,
    register_tools,
)
from entrascope.models import AuthSource

log = get_logger(__name__)

#: The surface name, which selects the logging format and destination.
SURFACE = "mcp_stdio"


def build_server(
    config: Config | None = None, requested: AuthSource | None = None
) -> FastMCP:
    """Build the local server with every tool registered.

    Logging goes to standard error as JSON lines, because standard output
    carries the protocol.
    """
    settings = config or load_config()
    configure_logging(settings, surface=SURFACE)
    # framework contract: FastMCP expresses a server as an object. Every tool
    # is a free function registered onto it.
    server = FastMCP(name=SERVER_NAME, instructions=INSTRUCTIONS)
    register_tools(server, settings, credential_factory(settings, requested), requested)
    log.info("local server ready", extra={"surface": SURFACE})
    return server


def run(server: FastMCP) -> None:
    """Run one server over stdio.

    The banner is suppressed. Standard output carries the protocol and standard
    error carries JSON lines, and a banner in either would be noise a parser has
    to cope with.
    """
    server.run(transport="stdio", show_banner=False)


def main(config_dir: Path | None = None, auth: AuthSource | None = None) -> None:
    """Run the local server over stdio."""
    run(build_server(load_config(config_dir), auth))
