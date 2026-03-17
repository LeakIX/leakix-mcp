# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `bulk_export` tool for bulk leak data export
- `quick_recon` tool for quick IP/domain reconnaissance
- `exposure_report` tool for security exposure analysis
- `find_related` tool for discovering related targets

### Changed

- Use official `leakix` library AsyncClient instead of custom httpx wrapper
- Use `Scope` enum and `AbstractResponse` from leakix client
- Upgrade l9format to 2.0.0, drop archived serde dependency ([4b8e300])
- Bump ruff from 0.14.14 to 0.15.5 ([eea2081])
- Support Python 3.11, 3.12, 3.13, and 3.14 ([f23cf81])
- Migrate from Poetry to uv ([9d899b9])
- Update dependabot to use uv package ecosystem ([935ea9d])
- CI: use Makefile targets in workflows and add per-commit testing
  ([8fe308e])
- Move changelog check into own workflow with external script,
  add shellcheck workflow ([d24c894])

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
[d24c894]: https://github.com/LeakIX/leakix-mcp/commit/d24c894
[8fe308e]: https://github.com/LeakIX/leakix-mcp/commit/8fe308e
[4b8e300]: https://github.com/LeakIX/leakix-mcp/commit/4b8e300
[eea2081]: https://github.com/LeakIX/leakix-mcp/commit/eea2081
[f23cf81]: https://github.com/LeakIX/leakix-mcp/commit/f23cf81
[9d899b9]: https://github.com/LeakIX/leakix-mcp/commit/9d899b9
[935ea9d]: https://github.com/LeakIX/leakix-mcp/commit/935ea9d
