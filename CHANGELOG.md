# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Upgrade l9format to 2.0.0, drop archived serde dependency ([4b8e300])
<<<<<<< HEAD
- Bump ruff from 0.14.14 to 0.15.5 ([eea2081])
=======
- Support Python 3.11, 3.12, 3.13, and 3.14 ([f23cf81])
>>>>>>> e2b594e (CHANGELOG: add Python 3.11+ support entry)

### Added

- Initial release with MCP server implementation
- `search_services` tool for searching exposed services
- `search_leaks` tool for searching data leaks
- `host_lookup` tool for IP address information
- `domain_lookup` tool for domain information
- `list_subdomains` tool for subdomain enumeration
- `list_plugins` tool for listing detection plugins
- Automatic rate limit handling
- GitHub Actions CI workflow

<!-- Commit links -->
[f23cf81]: https://github.com/LeakIX/leakix-mcp/commit/f23cf81
[4b8e300]: https://github.com/LeakIX/leakix-mcp/commit/4b8e300
[eea2081]: https://github.com/LeakIX/leakix-mcp/commit/eea2081
