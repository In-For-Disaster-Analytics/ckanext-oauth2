# OAuth2 CKAN extension

The OAuth2 extension allows site visitors to login through an OAuth2 server.

This extension is tested in CKAN 2.11. This is therefore considered as the supported version

## Installation

### Database Setup

After installing the extension, you need to initialize the database tables:

```bash
ckan -c /etc/ckan/default/ckan.ini db upgrade -p oauth2
```

This command will create the necessary `user_token` table for storing OAuth2 tokens.

To revert the database changes:

```bash
ckan -c /etc/ckan/default/ckan.ini db downgrade -p oauth2
```

## Configuration

### Environment Variables

The extension can be configured using environment variables. All configuration options can be set either through environment variables or through CKAN's configuration file. Environment variables take precedence over configuration file settings.

#### Required Configuration

The following environment variables are required for the extension to work:

```bash
# OAuth2 Server Configuration
CKAN_OAUTH2_AUTHORIZATION_ENDPOINT="https://oauth2-server/authorize"  # OAuth2 authorization endpoint
CKAN_OAUTH2_TOKEN_ENDPOINT="https://oauth2-server/token"             # OAuth2 token endpoint
CKAN_OAUTH2_CLIENT_ID="your-client-id"                              # OAuth2 client ID
CKAN_OAUTH2_CLIENT_SECRET="your-client-secret"                      # OAuth2 client secret
CKAN_OAUTH2_PROFILE_API_URL="https://oauth2-server/userinfo"        # User profile API endpoint
CKAN_OAUTH2_PROFILE_API_USER_FIELD="username"                       # Field name for username in profile response
CKAN_OAUTH2_PROFILE_API_MAIL_FIELD="email"                          # Field name for email in profile response
```

#### Optional Configuration

```bash
# SSL/TLS Configuration
OAUTHLIB_INSECURE_TRANSPORT=""                                      # Set to "1" to allow insecure transport (not recommended)
REQUESTS_CA_BUNDLE="/path/to/ca-bundle.crt"                        # Path to CA bundle for SSL verification

# JWT Configuration
CKAN_OAUTH2_JWT_ENABLE="false"                                      # Enable JWT token support
CKAN_OAUTH2_JWT_ALGORITHM="HS256"                                   # JWT algorithm (e.g., HS256, RS256, ES256)
CKAN_OAUTH2_JWT_SECRET="your-jwt-secret"                           # JWT secret for symmetric algorithms (HS256, HS384, HS512)
CKAN_OAUTH2_JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..."       # JWT public key for asymmetric algorithms (RS256, ES256, etc.)

# JWT Token Field Configuration (for custom JWT claim names)
CKAN_OAUTH2_JWT_USERNAME_FIELD="username"                          # JWT claim field for username (default: "username")
CKAN_OAUTH2_JWT_EMAIL_FIELD="email"                                # JWT claim field for email (default: "email")
CKAN_OAUTH2_JWT_FULLNAME_FIELD="name"                              # JWT claim field for full name (default: "name")
CKAN_OAUTH2_JWT_FIRSTNAME_FIELD="given_name"                       # JWT claim field for first name (default: "given_name")
CKAN_OAUTH2_JWT_LASTNAME_FIELD="family_name"                       # JWT claim field for last name (default: "family_name")

CKAN_OAUTH2_LEGACY_IDM="false"                                      # Enable legacy IDM support

# Profile API Field Configuration
CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD="fullname"                   # Field name for full name
CKAN_OAUTH2_PROFILE_API_FIRSTNAME_FIELD="firstname"                 # Field name for first name
CKAN_OAUTH2_PROFILE_API_LASTNAME_FIELD="lastname"                   # Field name for last name
CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD="groups"              # Field name for group membership
CKAN_OAUTH2_SYSADMIN_GROUP_NAME="sysadmin"                          # Group name for sysadmin role

# Response Unwrapping Configuration
# Some OAuth2 providers wrap API responses in an envelope (e.g. {"result": {...}}).
# Use dot-notation paths to navigate nested structures (e.g. "response.data").
# Leave empty for providers that return flat responses (standard OAuth2).
CKAN_OAUTH2_TOKEN_RESPONSE_PATH=""                                 # Dot-path to unwrap token response envelope (e.g. "result")
CKAN_OAUTH2_TOKEN_RESPONSE_KEY="access_token"                      # Key within unwrapped response holding the token payload
CKAN_OAUTH2_PROFILE_RESPONSE_PATH=""                               # Dot-path to unwrap profile response envelope (e.g. "result")

# URL Configuration
CKAN_OAUTH2_REGISTER_URL="https://oauth2-server/register"           # Registration URL
CKAN_OAUTH2_RESET_URL="https://oauth2-server/reset"                 # Password reset URL
CKAN_OAUTH2_EDIT_URL="https://oauth2-server/edit"                   # Profile edit URL

# Header Configuration
CKAN_OAUTH2_AUTHORIZATION_HEADER="Authorization"                    # Authorization header name
CKAN_OAUTH2_REMEMBER_NAME="auth_tkt"                               # Remember me cookie name
```

### Field Configuration: JWT vs Profile API

This extension supports two different methods for retrieving user information:

1. **JWT Token Claims** (when `CKAN_OAUTH2_JWT_ENABLE=true`): Extracts user data from JWT access token claims
2. **Profile API** (always available): Fetches user data from the OAuth2 provider's userinfo/profile endpoint

These two methods use different field configurations because the data comes from different sources with potentially different field names.

#### JWT Token Field Configuration

When JWT is enabled, configure these to match the **claim names** in your provider's JWT tokens:

**Standard JWT Claims (Default):**
- `CKAN_OAUTH2_JWT_USERNAME_FIELD="username"` - JWT claim for username
- `CKAN_OAUTH2_JWT_EMAIL_FIELD="email"` - JWT claim for email
- `CKAN_OAUTH2_JWT_FULLNAME_FIELD="name"` - JWT claim for full name
- `CKAN_OAUTH2_JWT_FIRSTNAME_FIELD="given_name"` - JWT claim for first name
- `CKAN_OAUTH2_JWT_LASTNAME_FIELD="family_name"` - JWT claim for last name

**Custom/Namespaced JWT Claims (e.g., Tapis):**

Some providers use custom or namespaced claim names. For example, Tapis uses claims like `tapis/username`:

```bash
CKAN_OAUTH2_JWT_USERNAME_FIELD="tapis/username"
CKAN_OAUTH2_JWT_EMAIL_FIELD="tapis/email"
CKAN_OAUTH2_JWT_FIRSTNAME_FIELD="tapis/given_name"
CKAN_OAUTH2_JWT_LASTNAME_FIELD="tapis/family_name"
```

#### Profile API Field Configuration

Configure these to match the **field names** in your provider's profile/userinfo API response:

- `CKAN_OAUTH2_PROFILE_API_USER_FIELD` - Username field in API response
- `CKAN_OAUTH2_PROFILE_API_MAIL_FIELD` - Email field in API response
- `CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD` - Full name field in API response
- `CKAN_OAUTH2_PROFILE_API_FIRSTNAME_FIELD` - First name field in API response
- `CKAN_OAUTH2_PROFILE_API_LASTNAME_FIELD` - Last name field in API response
- `CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD` - Group membership field in API response

#### Complementary Data Sources

When JWT is enabled, the extension will:
1. First extract user data from the JWT token claims
2. Then attempt to fetch additional data from the profile API to complement missing fields
3. JWT data takes priority - profile API data only fills in missing fields

This allows providers like Tapis to provide minimal data in JWT (e.g., just `tapis/username`) while additional information (email, full name) can be fetched from the profile API.

### Response Unwrapping

Some OAuth2 providers wrap their API responses in an envelope. For example, Tapis returns token responses as:

```json
{"result": {"access_token": {"access_token": "...", "token_type": "Bearer", ...}}}
```

And profile responses as:

```json
{"result": {"username": "john", "email": "john@example.com", ...}}
```

The response unwrapping configuration handles this in two steps:

1. **`CKAN_OAUTH2_TOKEN_RESPONSE_PATH`**: A dot-separated path to navigate the token response envelope. For Tapis, set to `result`.
2. **`CKAN_OAUTH2_TOKEN_RESPONSE_KEY`**: The key within the unwrapped response that holds the actual token payload dict. Defaults to `access_token`.
3. **`CKAN_OAUTH2_PROFILE_RESPONSE_PATH`**: A dot-separated path to navigate the profile response envelope. For Tapis, set to `result`.

For deeply nested responses, use dot-notation (e.g. `response.data.user`).

For standard OAuth2 providers that return flat responses, leave these empty (the default) and no unwrapping will occur.

**Example: Tapis configuration**

```bash
CKAN_OAUTH2_TOKEN_RESPONSE_PATH=result
CKAN_OAUTH2_TOKEN_RESPONSE_KEY=access_token
CKAN_OAUTH2_PROFILE_RESPONSE_PATH=result
```

### Security Considerations

1. **SSL/TLS**: Always use HTTPS for OAuth2 endpoints. The `OAUTHLIB_INSECURE_TRANSPORT` should only be used in development environments.

2. **Client Credentials**: Keep your `CKAN_OAUTH2_CLIENT_ID` and `CKAN_OAUTH2_CLIENT_SECRET` secure and never commit them to version control.

3. **CA Bundle**: When using self-signed certificates, provide the correct CA bundle path using `REQUESTS_CA_BUNDLE`.

4. **JWT Security**: When JWT is enabled, you must provide the appropriate key for signature verification:
   - For symmetric algorithms (HS256, HS384, HS512): Use `CKAN_OAUTH2_JWT_SECRET`
   - For asymmetric algorithms (RS256, ES256, etc.): Use `CKAN_OAUTH2_JWT_PUBLIC_KEY`
   - The public key must be in PEM format with proper line breaks (use `\n` in environment variables)
   - Ensure the key has exactly 5 dashes in the BEGIN/END markers: `-----BEGIN PUBLIC KEY-----`
   - Without the appropriate key, JWT tokens will be rejected for security

## Links

1. [Activating & Installing the plugin](https://github.com/conwetlab/ckanext-oauth2/wiki/Activating-and-Installing)
2. [Starting CKAN over HTTPs](https://github.com/conwetlab/ckanext-oauth2/wiki/Starting-CKAN-over-HTTPs)
3. [How it works?](https://github.com/conwetlab/ckanext-oauth2/wiki/How-it-works%3F)

## Credits

Based on the idea proposed by [Etalab](https://github.com/etalab/ckanext-oauth2)
