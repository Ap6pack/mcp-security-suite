# Changelog

All notable changes to the MCP Security Tools Suite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-08-30

### Added
- Interactive setup wizard (`setup_wizard.py`) with guided and manual configuration options
- Comprehensive MCP Integration Guide (`MCP_INTEGRATION_GUIDE.md`) showing:
  - Custom Python client examples
  - Web-based interface examples (Flask)
  - REST API gateway examples (FastAPI)
  - CI/CD integration (GitHub Actions, Jenkins)
  - Docker and Kubernetes deployment configurations
  - Production-ready client with caching and metrics
- Getting Started guide (`GETTING_STARTED.md`) for 5-minute quick start
- Example Claude Desktop configuration file (`claude_desktop_config.example.json`)

### Changed
- All MCP servers now display helpful messages when run directly
- Updated `test_servers.py` to reference the setup wizard
- Renamed `mcpGuide.md` to `TECHNICAL_REFERENCE.md` for clarity
- Improved README.md structure with links to Getting Started and Integration guides
- Enhanced troubleshooting section with common beginner issues

### Improved
- User experience for beginners with clear explanations of MCP servers
- Documentation structure to eliminate confusion and duplication
- Error messages and server output to be more user-friendly

## [1.0.0] - 2025-08-30

### Added
- Initial release of MCP Security Tools Suite
- Core security assessment server (`security_server.py`)
- Attack Surface Management server (`asm_server.py`)
- Penetration testing server (`pentest_server.py`)
- Red team operations server (`redteam_server.py`)
- Custom MCP client implementation (`custom_client.py`)
- Comprehensive test suite (`test_servers.py`)
- Project documentation (README.md)
- Security policies (SECURITY.md)
- Contributing guidelines (CONTRIBUTING.md)
- MIT License with security tool terms
- Example environment configuration (.example_env)
- Python dependencies (requirements.txt)
- Git ignore configuration (.gitignore)

### Security
- Scope validation for authorized testing only
- Environment-based API key management
- Input validation and sanitization
- Rate limiting capabilities
- Audit logging functionality

---

*The MCP Security Tools Suite provides ethical security testing capabilities through the Model Context Protocol.*
