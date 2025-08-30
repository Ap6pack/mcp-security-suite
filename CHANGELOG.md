# Changelog

All notable changes to the MCP Security Tools Suite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

*This is the first public release of the MCP Security Tools Suite.*
