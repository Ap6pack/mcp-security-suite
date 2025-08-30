# Contributing to MCP Security Tools Suite

Thank you for your interest in contributing to the MCP Security Tools Suite! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to:
- Use these tools ethically and legally
- Respect the security community
- Help maintain a welcoming environment
- Report security issues responsibly

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the issue template** when creating new issues
3. **Include**:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version)
   - Relevant logs or error messages

### Suggesting Features

1. **Check the roadmap** in README.md
2. **Open a discussion** before implementing major features
3. **Explain**:
   - Use case for the feature
   - How it benefits security professionals
   - Potential implementation approach

### Submitting Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**: `git commit -m "Add feature: description"`
6. **Push to your fork**: `git push origin feature/your-feature-name`
7. **Open a Pull Request**

## Development Setup

### Prerequisites

```bash
# Python 3.8 or higher
python --version

# Virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=.

# Run specific test file
pytest test_security_server.py

# Run security checks
bandit -r . -f json
safety check
```

### Code Style

We use the following tools to maintain code quality:

```bash
# Format code with Black
black .

# Check style with flake8
flake8 .

# Type checking with mypy
mypy .

# Security linting with bandit
bandit -r .
```

### Pre-commit Hooks

Set up pre-commit hooks to automatically check your code:

```bash
# Install pre-commit
pip install pre-commit

# Set up hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

## Coding Standards

### Python Style Guide

1. **Follow PEP 8**
2. **Use type hints** for function parameters and returns
3. **Write docstrings** for all public functions and classes
4. **Keep functions small** and focused
5. **Use meaningful variable names**

### Security Best Practices

1. **Input Validation**
   ```python
   def scan_target(target: str) -> dict:
       # Validate target is in authorized scope
       if not is_authorized(target):
           raise UnauthorizedTargetError(f"Target {target} not in scope")
       
       # Validate input format
       if not is_valid_domain(target) and not is_valid_ip(target):
           raise InvalidTargetError(f"Invalid target format: {target}")
   ```

2. **Error Handling**
   ```python
   try:
       result = perform_scan(target)
   except NetworkError as e:
       # Log detailed error internally
       logger.error(f"Network error scanning {target}: {e}")
       # Return generic error to user
       return {"error": "Network error occurred"}
   ```

3. **Secure Defaults**
   ```python
   def create_scanner(
       timeout: int = 30,  # Conservative timeout
       max_threads: int = 5,  # Limited concurrency
       verify_ssl: bool = True,  # SSL verification on by default
       follow_redirects: bool = False  # Don't follow redirects by default
   ):
       pass
   ```

### Documentation

1. **Function Documentation**
   ```python
   def check_ssl_certificate(domain: str, port: int = 443) -> dict:
       """
       Check SSL certificate validity and configuration.
       
       Args:
           domain: The domain to check
           port: The port to connect to (default: 443)
           
       Returns:
           dict: Certificate information including:
               - valid: bool
               - issuer: str
               - subject: str
               - not_before: datetime
               - not_after: datetime
               - errors: list[str]
               
       Raises:
           ConnectionError: If unable to connect to the domain
           ValueError: If domain format is invalid
       """
   ```

2. **Module Documentation**
   ```python
   """
   security_server.py
   
   MCP server providing core security assessment tools.
   
   This module implements various security checks including:
   - SSL certificate validation
   - Security header analysis
   - DNS lookups
   - CVE database queries
   """
   ```

## Testing Guidelines

### Unit Tests

1. **Test file naming**: `test_<module_name>.py`
2. **Test function naming**: `test_<function_name>_<scenario>`
3. **Use pytest fixtures** for common setup
4. **Mock external dependencies**

Example:
```python
import pytest
from unittest.mock import Mock, patch

@pytest.fixture
def mock_dns_resolver():
    with patch('dns.resolver.resolve') as mock:
        yield mock

def test_dns_lookup_success(mock_dns_resolver):
    # Arrange
    mock_dns_resolver.return_value = Mock(
        rrset=[Mock(to_text=lambda: '192.168.1.1')]
    )
    
    # Act
    result = dns_lookup('example.com', 'A')
    
    # Assert
    assert result['success'] is True
    assert '192.168.1.1' in result['records']
```

### Integration Tests

1. **Use test fixtures** for setup/teardown
2. **Test against mock services** when possible
3. **Never test against real targets** without permission

### Security Tests

1. **Test input validation**
2. **Test authorization checks**
3. **Test rate limiting**
4. **Test error handling**

## Commit Message Guidelines

Follow the conventional commits specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `security`: Security improvements

Example:
```
feat(scanner): add support for custom user agents

- Allow users to specify custom user agents for scans
- Add validation for user agent strings
- Update documentation with examples

Closes #123
```

## Review Process

### What We Look For

1. **Security**: No vulnerabilities introduced
2. **Quality**: Clean, maintainable code
3. **Testing**: Adequate test coverage
4. **Documentation**: Clear documentation
5. **Performance**: No significant performance regressions

### Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Security checks pass (bandit, safety)
- [ ] Documentation is updated
- [ ] No hardcoded credentials or secrets
- [ ] Input validation is implemented
- [ ] Error handling is appropriate
- [ ] Changes are backwards compatible

## Release Process

1. **Version Bumping**: We use semantic versioning (MAJOR.MINOR.PATCH)
2. **Changelog**: Update CHANGELOG.md with notable changes
3. **Testing**: All tests must pass
4. **Security Scan**: Full security audit before release
5. **Documentation**: Ensure all docs are up to date
6. **Tag Release**: Create git tag for the version

## Getting Help

- **Discord**: [Join our Discord server]
- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Use GitHub Issues for bugs and features
- **Security**: See SECURITY.md for security issues

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Security acknowledgments (for security fixes)

Thank you for helping make MCP Security Tools Suite better and more secure!
