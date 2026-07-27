# LeakIX MCP

An [MCP](https://modelcontextprotocol.io) server exposing the
[LeakIX](https://leakix.net) API for security research and reconnaissance.

It runs over the stdio transport by default and registers a set of tools
(host and domain lookups, service and leak search, subdomain enumeration,
bulk export, and higher-level recon/reporting helpers) plus a usage-guide
resource.

## Quick start

```bash
uv sync
LEAKIX_API_KEY=<your-key> uv run leakix-mcp
```

Get an API key from <https://leakix.net/settings>.

## Transports

- **stdio** (default): the standard MCP transport; the API key comes from
  the `LEAKIX_API_KEY` environment variable.
- **HTTP** (experimental, off by default): the Streamable HTTP transport is
  gated behind `LEAKIX_MCP_ENABLE_HTTP=1` and takes a listen address via
  `--server-address`. It is not production-ready.

## Documentation

- [Tools](tools.md) - the tools this server exposes.
- [API reference](reference.md) - module and function documentation.
