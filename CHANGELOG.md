# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Infrastructure

- CI: add PR hygiene checks using dannywillems/toolbox ([c3b9f1f])

### Changed

- Upgrade l9format to 2.0.0, drop archived serde dependency ([4b8e300])
- Bump ruff from 0.14.14 to 0.15.5 ([eea2081])
- Support Python 3.11, 3.12, 3.13, and 3.14 ([f23cf81])
- Migrate from Poetry to uv ([9d899b9])
- Update dependabot to use uv package ecosystem ([935ea9d])
- CI: use Makefile targets in workflows and add per-commit testing
  ([8fe308e])
- Move changelog check into own workflow with external script,
  add shellcheck workflow ([d24c894])
- Makefile: add `publish` and `publish-dry-run` targets ([56b5cb1])
- Use explicit include list for hatch sdist build target in
  `pyproject.toml` ([c931e39])
- Update l9format requirement from >=2.0.0 to >=2.0.1 ([8a14e28])

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
[8a14e28]: https://github.com/LeakIX/leakix-mcp/commit/8a14e28
[56b5cb1]: https://github.com/LeakIX/leakix-mcp/commit/56b5cb1
[c931e39]: https://github.com/LeakIX/leakix-mcp/commit/c931e39
[c3b9f1f]: https://github.com/LeakIX/leakix-mcp/commit/c3b9f1f
[d24c894]: https://github.com/LeakIX/leakix-mcp/commit/d24c894
[8fe308e]: https://github.com/LeakIX/leakix-mcp/commit/8fe308e
[4b8e300]: https://github.com/LeakIX/leakix-mcp/commit/4b8e300
[eea2081]: https://github.com/LeakIX/leakix-mcp/commit/eea2081
[f23cf81]: https://github.com/LeakIX/leakix-mcp/commit/f23cf81
[9d899b9]: https://github.com/LeakIX/leakix-mcp/commit/9d899b9
[935ea9d]: https://github.com/LeakIX/leakix-mcp/commit/935ea9d
