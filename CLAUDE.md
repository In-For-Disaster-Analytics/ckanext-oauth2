# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a CKAN extension that provides OAuth2 authentication support. The extension allows CKAN users to authenticate through external OAuth2 providers instead of using local CKAN accounts.

## Core Architecture

### Main Components

- **OAuth2Helper** (`ckanext/oauth2/oauth2.py`): Core OAuth2 functionality including token handling, user profile fetching, and JWT support
- **OAuth2Plugin** (`ckanext/oauth2/plugin.py`): CKAN plugin implementation that integrates OAuth2 into CKAN's authentication system
- **Database models** (`ckanext/oauth2/db.py`): User state management for OAuth2 sessions
- **Views** (`ckanext/oauth2/views.py`): Flask blueprint for OAuth2 endpoints
- **CLI commands** (`ckanext/oauth2/cli.py`): Command-line tools for OAuth2 management

### Key Features

- OAuth2 authorization code flow
- JWT token support with configurable algorithms (HS256, RS256, ES256, etc.)
- User profile synchronization from OAuth2 provider
- Group membership mapping from OAuth2 provider
- Legacy IDM compatibility mode
- Comprehensive configuration via environment variables

## Development Commands

### Installation and Setup
```bash
# Install dependencies and dev dependencies using uv
uv sync --dev
```

### Running Tests

Tests use `uv run` with the `CKAN_INI` environment variable pointing to `test.ini`. All commands should be run from the extension root directory (`src/ckanext-oauth2/`).

```bash
# Run all tests
CKAN_INI=test.ini uv run pytest

# Run all tests with verbose output
CKAN_INI=test.ini uv run pytest -v

# Run tests with coverage
CKAN_INI=test.ini uv run pytest --cov=ckanext.oauth2

# Run a specific test file
CKAN_INI=test.ini uv run pytest ckanext/oauth2/tests/test_oauth2.py

# Run a specific test class
CKAN_INI=test.ini uv run pytest ckanext/oauth2/tests/test_oauth2.py::TestOAuth2Plugin

# Run a specific test method
CKAN_INI=test.ini uv run pytest ckanext/oauth2/tests/test_oauth2.py::TestOAuth2Plugin::test_method_name -v
```

**Note:** `pytest.ini` already configures `--ckan-ini test.ini` and sets `testpaths = ckanext/oauth2/tests`, but the `CKAN_INI` environment variable is still required for CKAN's internal configuration loading.

### Code Quality
```bash
# Check PEP8 compliance (ignores E501 line length)
uv run flake8 ckanext/
```

## Configuration

The extension is primarily configured through environment variables (see README.md for complete list). Key configuration includes:

- OAuth2 server endpoints (authorization, token, userinfo)
- Client credentials
- JWT configuration (algorithm, keys/secrets)
- User profile field mappings
- Group membership settings

Test configuration is in `test.ini` and `test-fiware.ini` files.

## Testing Strategy

- Unit tests for OAuth2Helper class (`test_oauth2.py`)
- Plugin integration tests (`test_plugin.py`)  
- Database model tests (`test_db.py`)
- Controller/view tests (`test_controller.py`)
- Tests use parameterized testing and httpretty for HTTP mocking

## Security Considerations

- JWT token verification is enforced when JWT is enabled
- Access tokens are validated for expiration
- Client secrets must be kept secure
- HTTPS enforcement for OAuth2 endpoints (configurable for development)
- Proper state parameter handling to prevent CSRF attacks