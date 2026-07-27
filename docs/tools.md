# Tools

The server registers the following MCP tools. Each tool's arguments are
validated against a schema generated from a pydantic model, and any LeakIX
API failure is surfaced as an MCP error rather than an empty result.

| Tool | Purpose | Arguments |
|---|---|---|
| `host_lookup` | Services and leaks for an IP | `ip` |
| `domain_lookup` | Services and leaks for a domain | `domain` |
| `list_subdomains` | Enumerate discovered subdomains | `domain` |
| `list_plugins` | Available LeakIX detection plugins | (none) |
| `search_services` | Search exposed services | `query`, `page` |
| `search_leaks` | Search data leaks | `query`, `page` |
| `bulk_export` | Bulk export (Pro API) | `query` |
| `quick_recon` | Auto host/domain recon | `target` |
| `find_related` | Related targets by tech/ASN/network | `target`, `relation_type` |
| `exposure_report` | Structured exposure report | `target` |

`host_lookup` accepts IPv4 or IPv6; `domain_lookup` and `list_subdomains`
validate the argument as an RFC 1123 hostname. `quick_recon`,
`find_related`, and `exposure_report` accept either an IP or a hostname and
route accordingly.
