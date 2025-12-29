# CHANGELOG

<!-- version list -->

## v1.0.0-beta.16 (2025-12-29)

### Bug Fixes

- Force
  ([`aa7a648`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/aa7a648271b84098fb6184e024b6cf2db907cf5f))

### Refactoring

- Replace remember() with login_user() for authentication
  ([`2002129`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/200212969defe786770fcd407e17fcda551f7213))


## v1.0.0-beta.15 (2025-12-28)

### Bug Fixes

- Force
  ([`8769343`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/87693434b5b6409103245bc974fd53c7b7c6c6a6))


## v1.0.0-beta.14 (2025-12-28)

### Bug Fixes

- **oauth2**: Preserve authentication cookies in callback redirect
  ([`712fa46`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/712fa46061ebcb3c6f7c7413e5696f1d7bbba894))

### Testing

- **oauth2**: Update tests for request.args migration
  ([`d45844f`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/d45844fc5c01aae835808967502279079aa36b94))


## v1.0.0-beta.13 (2025-12-28)

### Bug Fixes

- Print log
  ([`a7a5f07`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/a7a5f078a107b7075d17f2bff390d2c526acdffd))


## v1.0.0-beta.12 (2025-12-28)

### Features

- **oauth2**: Add configurable JWT field names and complementary profile merging
  ([`bb8abbe`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/bb8abbe52df953a5c75f3e9a00dd402e37ead14a))

### Testing

- Add test for profile API field mismatch handling
  ([`838da07`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/838da0769963f5eef5c43dd362c24a30fd7c5e1e))


## v1.0.0-beta.11 (2025-10-19)

### Bug Fixes

- Force 10
  ([`f0c57b1`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/f0c57b1a4f547ecfe3396421a51b80da2cde1da8))

- Force release 10
  ([`ee357ac`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/ee357ac859d41c5a84122f7914ccaa7365808b7d))


## v1.0.0-beta.10 (2025-10-19)

### Bug Fixes

- **views**: Import get_came_from function correctly
  ([`95295ee`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/95295ee3ca7d40dd674c3c7edbb11df3e71b245d))


## v1.0.0-beta.9 (2025-10-19)

### Bug Fixes

- **jwt**: Convert escaped newlines in PEM public key
  ([`8035dbb`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/8035dbbd87c4f48db85752fda2296aba04fb8fdd))

- **views**: Use request.args instead of request.GET for Flask
  ([`7f3e0a4`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/7f3e0a47a0ca4c87f996221080d5bd05e072d8ec))


## v1.0.0-beta.8 (2025-10-19)

### Features

- **jwt**: Add cryptography dependency for RS256 support
  ([`617586f`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/617586f681202501884b87ba7379100a7534cf6d))


## v1.0.0-beta.7 (2025-10-19)

### Bug Fixes

- Force release
  ([`f6b7149`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/f6b71491ea25e78703cccdb87ee1b8a96d834d61))

### Refactoring

- **oauth2**: Require config parameter in OAuth2Helper
  ([`6451bd9`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/6451bd9f09feb9b0968aaada2c7c9c532fcb2c1c))


## v1.0.0-beta.6 (2025-10-19)

### Features

- **plugin**: Add debug logging for OAuth2Helper initialization
  ([`d47314b`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/d47314b747b9eb5996260fbcdd33e8a113375ea5))


## v1.0.0-beta.5 (2025-10-19)

### Bug Fixes

- **oauth2**: Remove invalid session.save() call and add debug logging
  ([`616c39a`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/616c39a677a0464d8ca15d0733e242e02f734ea2))

- **plugin**: Initialize OAuth2Helper in update_config
  ([`7fe1ab3`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/7fe1ab3e5ebf2193e840b0e007610f8595efb966))


## v1.0.0-beta.4 (2025-10-18)

### Bug Fixes

- Readme
  ([`c66dae3`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/c66dae3ace704dcfe9d207431fbc5360dc7b9571))

### Build System

- Remove legacy setup.py in favor of pyproject.toml
  ([`083da38`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/083da38a90bbe8c2567fa828de8caeab1cd789d9))

- Update repository URLs to TACC organization
  ([`bf06265`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/bf062650d305e063c38a78be46bff523c856fdfe))

### Continuous Integration

- Update workflow to use pip install instead of setup.py
  ([`48c7209`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/48c72098b3413ffeaa91a4724653354ec788cde9))


## v1.0.0-beta.3 (2025-10-18)

### Bug Fixes

- Update readme
  ([`5676b06`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/5676b06197136253ef99310e93df685046186ba1))

### Refactoring

- **db**: Simplify database model initialization
  ([`23f55a4`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/23f55a4a3b968fc1a7ceab935894a7fe558f8d5b))


## v1.0.0-beta.2 (2025-10-18)

### Features

- **db**: Migrate to Alembic for database schema management
  ([`ccbbdf3`](https://github.com/In-For-Disaster-Analytics/ckanext-oauth2/commit/ccbbdf3dd961792f57636bea31b5b2585ef3051c))

## v1.0.0-beta.1 (2025-10-18)

- Initial Release
