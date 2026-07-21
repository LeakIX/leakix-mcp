# Agent Skills

## LeakIX Query Syntax

### Field Filters
- ip:1.2.3.4 - Search by IP address
- host:example.com - Search by hostname (also matches subdomains)
- host:tld - Search by TLD
- asn:1234 - Search by ASN number
- geoip.country_iso_code:US - Search by country code (ISO 2-letter)
- port:22 - Search by port number
- protocol:ssh - Search by protocol (ssh, http, https, ftp, etc.)
- transport:tcp - Search by transport (tcp, udp)
- software.name:nginx - Search by software name
- software.version:1.0 - Search by software version
- plugin:PluginName - Search by vulnerability/leak plugin name
- tag:cve-2022-22222 - Search by tag, usually CVEs, lowercase

### Operators
- + (require): +geoip.country_iso_code:FR +port:22 - both conditions
- - (exclude): +apache -nginx - Apache but not nginx
- No operator: plugin:A plugin:B - A or B
- Quotes for exact match: "Apache/2.4.41"

### Examples
- SSH in France: +protocol:ssh +geoip.country_iso_code:FR
- Exposed MongoDB: +port:27017
- Apache in AS1234: +software.name:apache +asn:1234
- Services on a domain: +domain:example.com
- GitConfig leaks: +plugin:GitConfigHttpPlugin

Always combine multiple filters for precise results.

## Plugins vs Services

Users are usually more interested in plugins (vulnerabilities/leaks) than raw services.
- Plugins are searched with `search_leaks`, NOT `search_services`.
- If a user asks about a software, check `list_plugins` for a matching plugin first.
- Fall back to `search_services` only if no relevant plugin exists.

## Workflows

### Initial reconnaissance
1. `quick_recon` for a fast first look (auto-detects IP vs domain)
2. `list_subdomains` to map the attack surface
3. `search_leaks` with relevant plugins to find exposures

### Security assessment
1. `exposure_report` for a structured risk summary
2. `search_leaks` with +plugin: or +leak.severity:critical for details
3. `find_related` (technology/asn/network) to expand scope

### Targeted investigation
- Known IP: `host_lookup` then `search_leaks` with +ip:
- Known domain: `domain_lookup` then `list_subdomains`
- Pivot from a finding: `find_related` to discover similar targets

### Large-scale export
- `bulk_export` (Pro API) for aggregated datasets

## General Guidelines
- Prefer `search_leaks` over `search_services` for vulnerability questions
- Use `list_plugins` to discover plugin names before constructing leak queries
- Pagination is 0-indexed; iterate pages for complete results
- Always construct precise queries combining multiple filters
