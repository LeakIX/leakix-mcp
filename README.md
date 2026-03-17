# LeakIX MCP Server

MCP server for the [LeakIX](https://leakix.net) API.

## Quick start

Get your API key from [leakix.net/settings](https://leakix.net/settings), then:

```bash
# Claude Code
claude mcp add -e LEAKIX_API_KEY=your-key -- leakix \
  uvx --from leakix-mcp leakix-mcp

# Claude Desktop (~/.config/claude/claude_desktop_config.json)
{
  "mcpServers": {
    "leakix": {
      "command": "uvx",
      "args": ["--from", "leakix-mcp", "leakix-mcp"],
      "env": { "LEAKIX_API_KEY": "your-key" }
    }
  }
}
```

Restart Claude and ask: "look up the domain leakix.net"

## Tools

| Tool | What it does |
|------|-------------|
| `search_services` | Find exposed services (`+port:22 +country:"FR"`) |
| `search_leaks` | Find data leaks (`+leak.severity:critical`) |
| `host_lookup` | Get info on an IP address |
| `domain_lookup` | Get info on a domain |
| `list_subdomains` | Enumerate subdomains |
| `list_plugins` | List detection plugins |
| `bulk_export` | Bulk export leaks (Pro API) |
| `quick_recon` | Auto recon on an IP or domain |
| `exposure_report` | Security exposure report with risk level |
| `find_related` | Find related targets by tech, ASN, or network |

Query syntax: `+field:value`, `-field:value`, `field:>100`,
`field:"exact phrase"`.
Full docs: [docs.leakix.net](https://docs.leakix.net/docs/query/fields/)

## Development

```bash
make setup   # install deps
make check   # format + lint + typecheck
make test    # run tests
```

## License

MIT
