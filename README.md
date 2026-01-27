# LeakIX MCP Server

An MCP (Model Context Protocol) server for the [LeakIX](https://leakix.net) API,
enabling security research and reconnaissance through Claude and other MCP
clients.

## Features

- **Service Search**: Find exposed services, open ports, and running software
- **Leak Search**: Discover data leaks and exposed databases
- **Host Lookup**: Get detailed information about specific IP addresses
- **Domain Lookup**: Investigate domains and their associated services
- **Subdomain Enumeration**: List discovered subdomains
- **Plugin Discovery**: Browse available detection plugins

## Installation

### Using pip

```bash
pip install leakix-mcp
```

### From source

```bash
git clone https://github.com/LeakIX/leakix-mcp.git
cd leakix-mcp
make setup
```

## Configuration

Set your LeakIX API key as an environment variable:

```bash
export LEAKIX_API_KEY="your-api-key-here"
```

Get your API key from [LeakIX Settings](https://leakix.net/settings).

### Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "leakix": {
      "command": "leakix-mcp",
      "env": {
        "LEAKIX_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Claude Code

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "leakix": {
      "command": "leakix-mcp",
      "env": {
        "LEAKIX_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Available Tools

### search_services

Search for exposed services using LeakIX query syntax.

**Parameters:**
- `query` (required): Search query (e.g., `+country:"US" +port:22`)
- `page` (optional): Page number (default: 0)

**Example queries:**
- `+country:"France" +port:3306` - MySQL servers in France
- `+plugin:OpenSSH` - OpenSSH servers
- `+ip:192.168.0.0/16` - Services in a CIDR range

### search_leaks

Search for data leaks and exposed databases.

**Parameters:**
- `query` (required): Search query
- `page` (optional): Page number (default: 0)

**Example queries:**
- `+leak.severity:critical` - Critical severity leaks
- `+leak.dataset.rows:>10000` - Leaks with more than 10k rows
- `+plugin:GitConfigHttpPlugin` - Exposed Git configurations

### host_lookup

Get information about a specific IP address.

**Parameters:**
- `ip` (required): IPv4 or IPv6 address

### domain_lookup

Get information about a domain and its subdomains.

**Parameters:**
- `domain` (required): Domain name (e.g., `example.com`)

### list_subdomains

Enumerate discovered subdomains for a domain.

**Parameters:**
- `domain` (required): Domain name

### list_plugins

Get available LeakIX detection plugins.

## Query Syntax

LeakIX uses a powerful query syntax:

- `+field:value` - Must match
- `-field:value` - Must not match
- `field:>100` - Range queries
- `field:"exact phrase"` - Phrase matching

### Common Fields

| Field | Description |
|-------|-------------|
| `ip` | IP address (supports CIDR) |
| `port` | Service port |
| `host` | Domain/hostname |
| `country` | Country name |
| `plugin` | Detection plugin |
| `leak.severity` | Leak severity level |
| `service.software.name` | Software name |

See [LeakIX Query Documentation](https://docs.leakix.net/docs/query/fields/)
for the full list of available fields.

## Development

```bash
# Setup development environment
make setup

# Run checks
make check

# Run tests
make test

# Format code
make format
```

## Rate Limiting

The LeakIX API is rate-limited to approximately 1 request per second. The client
automatically handles rate limiting by waiting when necessary.

## License

MIT
