# Changelog

All notable changes to the MCP Security Tools Suite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2025-09-08

### Added
- **Complete Business Impact Analysis Implementation**: All security servers now have comprehensive business impact analysis capabilities
  - **ASM Server**: Internet-facing asset exposure assessment, attack surface risk scoring, technology stack vulnerability analysis
  - **Pentest Server**: Vulnerability exploitability assessment, RCE detection, privilege escalation potential, authentication bypass analysis
  - **Red Team Server**: Attack path risk assessment, adversary capability analysis mapped to MITRE ATT&CK framework, operational risk evaluation
  - Executive-friendly summaries with clear business risk scoring and actionable recommendations
  - Compliance impact assessment for GDPR, PCI-DSS, SOX, and other regulatory frameworks
  - Strategic security investment prioritization with cost estimates and ROI indicators

### Enhanced
- **Business Risk Analysis**: Each server now provides context-specific business impact assessment
  - Advanced risk scoring algorithms tailored to each security domain
  - Crown jewel asset identification and exposure analysis
  - Financial impact calculations and business continuity assessments
  - Integration with regulatory compliance requirements

## [1.2.0] - 2025-09-08

### Added
- **FastMCP Integration**: Advanced client using FastMCP library (`advanced_client.py`)
  - Batch processing capabilities for multiple SSL checks
  - Multi-server coordination and management
  - High-level security assessment workflows
  - Async context managers for proper resource handling
- **Comprehensive Client Architecture**: Three-tier client system
  - **Basic Client** (`test_basic_client.py`): Simple JSON-RPC examples for learning
  - **Advanced Client** (`advanced_client.py`): FastMCP-powered production automation
  - **Production Client** (`custom_client.py`): Full interactive CLI with 30+ tools
- **Test Suite Expansion**: 
  - `test_advanced_client.py` for FastMCP functionality testing
  - `test_basic_client.py` for basic MCP protocol examples
- **Enhanced Documentation**:
  - Client comparison table in MCP Integration Guide
  - Client Options section in README with usage examples
  - Corrected import references throughout documentation

### Changed
- **Client File Structure**: Reorganized for clarity and alignment with documentation
  - Renamed `basic_client.py` → `test_basic_client.py` (matches integration guide)
  - Added proper FastMCP-based `advanced_client.py` 
  - Maintained `custom_client.py` as full production client
- **MCP Integration Guide**: Major updates to reflect new client architecture
  - Added comprehensive client comparison table
  - Fixed import statements to reference correct client files
  - Added FastMCP usage examples and advanced workflow patterns
- **Requirements**: Added `fastmcp>=2.12.2` dependency for advanced client features

### Enhanced
- **Business Impact Analysis**: Enhanced across all security servers with:
  - Advanced risk scoring algorithms
  - Asset categorization and impact assessment
  - Executive-friendly reporting capabilities
- **Server Architecture**: Improved error handling and JSON encoding across all servers
- **Development Experience**: Better separation of concerns between different client use cases

### Fixed
- **Import References**: Corrected all documentation examples to use proper client imports
- **Client Dependencies**: Ensured FastMCP integration works with existing server infrastructure
- **Documentation Consistency**: Aligned all documentation with actual file structure
- **File Organization**: Cleaned up obsolete and duplicate client files for clarity

### Removed
- Obsolete client file duplicates that were causing confusion
- Unused configuration files that were no longer needed

### Security
- **Maintained Authorization Controls**: All new clients maintain proper scope validation
- **Rate Limiting**: Advanced client includes proper rate limiting for batch operations
- **Connection Security**: Improved connection pooling and resource management

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
