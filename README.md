# OAuth2 CKAN extension

The OAuth2 extension allows site visitors to login through an OAuth2 server.

**Note**: This extension is being tested in CKAN 2.9. This is therefore considered as the supported version

Plans to support CKAN 2.10 and 2.11 are underway.

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
CKAN_OAUTH2_LEGACY_IDM="false"                                      # Enable legacy IDM support

# Profile API Field Configuration
CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD="fullname"                   # Field name for full name
CKAN_OAUTH2_PROFILE_API_FIRSTNAME_FIELD="firstname"                 # Field name for first name
CKAN_OAUTH2_PROFILE_API_LASTNAME_FIELD="lastname"                   # Field name for last name
CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD="groups"              # Field name for group membership
CKAN_OAUTH2_SYSADMIN_GROUP_NAME="sysadmin"                          # Group name for sysadmin role

# URL Configuration
CKAN_OAUTH2_REGISTER_URL="https://oauth2-server/register"           # Registration URL
CKAN_OAUTH2_RESET_URL="https://oauth2-server/reset"                 # Password reset URL
CKAN_OAUTH2_EDIT_URL="https://oauth2-server/edit"                   # Profile edit URL

# Header Configuration
CKAN_OAUTH2_AUTHORIZATION_HEADER="Authorization"                    # Authorization header name
CKAN_OAUTH2_REMEMBER_NAME="auth_tkt"                               # Remember me cookie name
```

### Security Considerations

1. **SSL/TLS**: Always use HTTPS for OAuth2 endpoints. The `OAUTHLIB_INSECURE_TRANSPORT` should only be used in development environments.

2. **Client Credentials**: Keep your `CKAN_OAUTH2_CLIENT_ID` and `CKAN_OAUTH2_CLIENT_SECRET` secure and never commit them to version control.

3. **CA Bundle**: When using self-signed certificates, provide the correct CA bundle path using `REQUESTS_CA_BUNDLE`.

## Links

1. [Activating & Installing the plugin](https://github.com/conwetlab/ckanext-oauth2/wiki/Activating-and-Installing)
2. [Starting CKAN over HTTPs](https://github.com/conwetlab/ckanext-oauth2/wiki/Starting-CKAN-over-HTTPs)
3. [How it works?](https://github.com/conwetlab/ckanext-oauth2/wiki/How-it-works%3F)

## Credits

Based on the idea proposed by [Etalab](https://github.com/etalab/ckanext-oauth2)
