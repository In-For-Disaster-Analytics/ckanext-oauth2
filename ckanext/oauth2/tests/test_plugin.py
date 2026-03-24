# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.

import sys
import pytest
import ckanext.oauth2.plugin as plugin
import jwt

from unittest.mock import MagicMock, patch

CUSTOM_AUTHORIZATION_HEADER = 'x-auth-token'
OAUTH2_AUTHORIZATION_HEADER = 'authorization'
HOST = 'ckan.theme.org'


@pytest.fixture
def plugin_setup():
    # Save functions and mock them
    original_toolkit = plugin.toolkit
    original_g = plugin.g
    original_current_user = plugin.current_user
    plugin.toolkit = MagicMock()
    plugin.toolkit.config = {
        'ckan.oauth2.authorization_header': OAUTH2_AUTHORIZATION_HEADER,
        'ckan.oauth2.authorization_endpoint': 'https://test.oauth.org/authorize',
        'ckan.oauth2.token_endpoint': 'https://test.oauth.org/token',
        'ckan.oauth2.client_id': 'test-client-id',
        'ckan.oauth2.client_secret': 'test-client-secret',
        'ckan.oauth2.profile_api_url': 'https://test.oauth.org/user',
        'ckan.oauth2.profile_api_user_field': 'id',
        'ckan.oauth2.profile_api_mail_field': 'email',
        'ckan.site_url': f'http://{HOST}:5000',
    }
    plugin.g = MagicMock()

    # Create the plugin
    oauth2_plugin = plugin.OAuth2Plugin()
    oauth2_plugin.update_config(plugin.toolkit.config)

    yield oauth2_plugin

    # Cleanup
    plugin.toolkit = original_toolkit
    plugin.g = original_g
    plugin.current_user = original_current_user


class TestPlugin:

    def _set_identity(self, identity):
        mock_user = MagicMock()
        if identity:
            mock_user.is_authenticated = True
            mock_user.name = identity
        else:
            mock_user.is_authenticated = False
            mock_user.name = None
        plugin.current_user = mock_user


    def test_auth_functions(self, plugin_setup):

        EXPECTED_AUTH_FUNCTIONS = ['user_create', 'user_update', 'user_reset', 'request_reset']

        auth_functions = plugin_setup.get_auth_functions()

        for auth_function in auth_functions:
            assert auth_function in EXPECTED_AUTH_FUNCTIONS
            function_result = auth_functions[auth_function]({'user': 'test'}, {})
            assert 'success' in function_result
            assert function_result['success'] is False

    @pytest.mark.parametrize("headers,authenticate_result,identity,expected_user,oauth2", [
        ({},                                              None,                      None,    None,    False),
        ({},                                              None,                      None,    None,    True),

        ({},                                              None,                      'test',  'test',  False),
        ({},                                              None,                      'test',  'test',  True),

        ({'invalid_header': 'api_key'},                   None,                      None,    None,    False),
        ({'invalid_header': 'api_key'},                   None,                      'test2', 'test2', False),
        ({'invalid_header': 'api_key'},                   None,                      None,    None,    True),
        ({'invalid_header': 'api_key'},                   None,                      'test2', 'test2', True),

        ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, 'test',                    None,    'test',  True),
        ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, 'test',                    'test2', 'test',  True),
        ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, ValueError('Invalid Key'), 'test2', 'test2', True),
        ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, ValueError('Invalid Key'), None,    None,    True),
        ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, None,                      'test2', 'test2', True),
        ({OAUTH2_AUTHORIZATION_HEADER: 'Otherr api_key'}, None,                      None,    None,    True),
        ({OAUTH2_AUTHORIZATION_HEADER: 'api_key'},        None,                      'test2', 'test2', True),
        ({OAUTH2_AUTHORIZATION_HEADER: 'api_key'},        None,                      None,    None,    True),

        ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'},        'test',                    None,    'test',  False),
        ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'},        'test',                    'test2', 'test',  False),
        ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'},        ValueError('Invalid Key'), 'test2', 'test2', False),
        ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'},        ValueError('Invalid Key'), None,    None,    False),
        ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'},        None,                      'test2', 'test2', False),

        # X-Tapis-Token: valid token authenticates user
        ({'X-Tapis-Token': 'api_key'},                                               'test',  None,    'test',  True),
        # X-Tapis-Token: valid token, session identity ignored in favor of token identity
        ({'X-Tapis-Token': 'api_key'},                                               'test',  'test2', 'test',  True),
        # Both headers present -- Authorization: Bearer wins
        ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key', 'X-Tapis-Token': 'other_key'}, 'test', None, 'test',  True),

    ])
    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify(self, mock_model, mock_login_user, plugin_setup, headers, authenticate_result, identity, expected_user, oauth2):
        mock_model.User.by_name.return_value = MagicMock()

        if not oauth2:
            plugin.toolkit.config = {
                'ckan.oauth2.authorization_header': CUSTOM_AUTHORIZATION_HEADER,
                'ckan.oauth2.authorization_endpoint': 'https://test.oauth.org/authorize',
                'ckan.oauth2.token_endpoint': 'https://test.oauth.org/token',
                'ckan.oauth2.client_id': 'test-client-id',
                'ckan.oauth2.client_secret': 'test-client-secret',
                'ckan.oauth2.profile_api_url': 'https://test.oauth.org/user',
                'ckan.oauth2.profile_api_user_field': 'id',
                'ckan.oauth2.profile_api_mail_field': 'email',
                'ckan.site_url': f'http://{HOST}:5000',
            }
            plugin_setup.update_config(plugin.toolkit.config)

        self._set_identity(identity)

        usertoken = {
            'access_token': 'current_access_token',
            'refresh_token': 'current_refresh_token',
            'token_type': 'current_token_type',
            'expires_in': '2678399'
        }
        newtoken = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'token_type': 'new_token_type',
            'expires_in': '3600'
        }

        def authenticate_side_effect(identity):
            if isinstance(authenticate_result, Exception):
                raise authenticate_result
            elif authenticate_result is not None:
                return (authenticate_result, MagicMock())
            else:
                return (None, None)

        plugin_setup.oauth2helper.identify = MagicMock(side_effect=authenticate_side_effect)
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=usertoken)
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=newtoken)
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(False, None))

        # Authentication header is not included
        plugin.toolkit.request.headers = headers

        # The identify function must set the user id in this variable
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.toolkit.g.usertoken_refresh = None

        # Call the function
        plugin_setup.identify()

        # Check that the function "authenticate" (called when the API Key is included) has not been called
        if oauth2 and OAUTH2_AUTHORIZATION_HEADER in headers:
            if headers[OAUTH2_AUTHORIZATION_HEADER].startswith('Bearer '):
                token = headers[OAUTH2_AUTHORIZATION_HEADER].replace('Bearer ', '')
            else:
                token = headers[OAUTH2_AUTHORIZATION_HEADER]
            plugin_setup.oauth2helper.identify.assert_called_once_with({'access_token': token})
        elif not oauth2 and CUSTOM_AUTHORIZATION_HEADER in headers:
            plugin_setup.oauth2helper.identify.assert_called_once_with({'access_token': headers[CUSTOM_AUTHORIZATION_HEADER]})
        elif 'X-Tapis-Token' in headers and OAUTH2_AUTHORIZATION_HEADER not in headers:
            plugin_setup.oauth2helper.identify.assert_called_once_with({'access_token': headers['X-Tapis-Token']})
        else:
            assert plugin_setup.oauth2helper.identify.call_count == 0

        assert expected_user == plugin.toolkit.g.user

        if expected_user is None:
            assert plugin.toolkit.g.usertoken is None
            assert plugin.toolkit.g.usertoken_refresh is None
        else:
            assert usertoken == plugin.toolkit.g.usertoken

            # method 'usertoken_refresh' should relay on the one provided by the oauth2 module
            plugin.toolkit.g.usertoken_refresh()
            plugin_setup.oauth2helper.refresh_token.assert_called_once_with(expected_user)
            assert newtoken == plugin.toolkit.g.usertoken

        # Verify login_user called when user is authenticated, not called otherwise
        if expected_user is not None:
            mock_login_user.assert_called_once()
        else:
            mock_login_user.assert_not_called()

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_expired_token_refresh_succeeds(self, mock_model, mock_login_user, plugin_setup):
        """Test expired JWT token in Authorization header triggers refresh successfully"""
        # Mock model.User.by_name to avoid database queries
        mock_user = MagicMock()
        mock_model.User.by_name.return_value = mock_user

        # Setup expired token scenario
        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.jwt_username_field = 'tapis/username'
        plugin_setup.oauth2helper.identify = MagicMock(side_effect=jwt.ExpiredSignatureError("Token expired"))
        plugin_setup.oauth2helper._decode_jwt = MagicMock(return_value={'tapis/username': 'testuser'})
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value={'access_token': 'new_token'})
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=None)

        # Set authorization header with expired token
        plugin.toolkit.request.headers = {OAUTH2_AUTHORIZATION_HEADER: 'Bearer expired_token'}
        plugin.toolkit.g.user = None
        plugin.g.user = None

        # Call identify
        plugin_setup.identify()

        # Verify refresh was called and user is authenticated
        plugin_setup.oauth2helper.refresh_token.assert_called_once_with('testuser')
        assert plugin.toolkit.g.user == 'testuser'

    @patch('ckanext.oauth2.plugin.login_user')
    def test_identify_expired_token_refresh_fails(self, mock_login_user, plugin_setup):
        """Test expired JWT token refresh failure leaves user unauthenticated"""
        # Mock current_user
        self._set_identity(None)

        # Setup expired token scenario with failed refresh
        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.jwt_username_field = 'tapis/username'
        plugin_setup.oauth2helper.identify = MagicMock(side_effect=jwt.ExpiredSignatureError("Token expired"))
        plugin_setup.oauth2helper._decode_jwt = MagicMock(return_value={'tapis/username': 'testuser'})
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=None)
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=None)

        # Set authorization header with expired token
        plugin.toolkit.request.headers = {OAUTH2_AUTHORIZATION_HEADER: 'Bearer expired_token'}
        plugin.toolkit.g.user = None
        plugin.g.user = None

        # Call identify
        plugin_setup.identify()

        # Verify user is NOT authenticated
        plugin_setup.oauth2helper.refresh_token.assert_called_once_with('testuser')
        assert plugin.toolkit.g.user is None

    @patch('ckanext.oauth2.plugin.login_user')
    def test_identify_expired_token_no_username(self, mock_login_user, plugin_setup):
        """Test expired token without username field in claims"""
        # Mock current_user
        self._set_identity(None)

        # Setup expired token scenario without username in claims
        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.jwt_username_field = 'tapis/username'
        plugin_setup.oauth2helper.identify = MagicMock(side_effect=jwt.ExpiredSignatureError("Token expired"))
        plugin_setup.oauth2helper._decode_jwt = MagicMock(return_value={})  # No username field
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value={'access_token': 'new_token'})
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=None)

        # Set authorization header with expired token
        plugin.toolkit.request.headers = {OAUTH2_AUTHORIZATION_HEADER: 'Bearer expired_token'}
        plugin.toolkit.g.user = None
        plugin.g.user = None

        # Call identify
        plugin_setup.identify()

        # Verify refresh was NOT called and user is NOT authenticated
        plugin_setup.oauth2helper.refresh_token.assert_not_called()
        assert plugin.toolkit.g.user is None

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_session_expired_token_refresh_succeeds(self, mock_model, mock_login_user, plugin_setup):
        """Test session auth with expired stored token triggers refresh successfully"""
        # Mock model.User.by_name to avoid database queries
        mock_user = MagicMock()
        mock_model.User.by_name.return_value = mock_user

        # Setup session-authenticated user
        self._set_identity('testuser')

        # Configure JWT and expired token check
        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.jwt_username_field = 'tapis/username'
        expired_token = {'access_token': 'expired_token'}
        new_token = {'access_token': 'new_token'}

        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=expired_token)
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(True, 'testuser'))
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=new_token)

        # No Authorization header (session path)
        plugin.toolkit.request.headers = {}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.g.user = None

        # Call identify
        plugin_setup.identify()

        # Verify token was refreshed
        plugin_setup.oauth2helper.check_token_expiration.assert_called_once_with('expired_token')
        plugin_setup.oauth2helper.refresh_token.assert_called_once_with('testuser')
        assert plugin.toolkit.g.usertoken == new_token

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.logout_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_session_expired_token_refresh_fails(self, mock_model, mock_logout, mock_login_user, plugin_setup):
        """Test session auth with expired stored token and failed refresh logs user out"""
        # Mock model.User.by_name to avoid database queries
        mock_user = MagicMock()
        mock_model.User.by_name.return_value = mock_user

        # Setup session-authenticated user
        self._set_identity('testuser')

        # Configure JWT and expired token check with failed refresh
        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.jwt_username_field = 'tapis/username'
        expired_token = {'access_token': 'expired_token'}

        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=expired_token)
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(True, 'testuser'))
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=None)

        # No Authorization header (session path)
        plugin.toolkit.request.headers = {}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.g.user = None

        # Call identify
        plugin_setup.identify()

        # Verify user is logged out when refresh fails
        assert plugin.toolkit.g.user is None
        assert plugin.toolkit.g.usertoken is None
        mock_logout.assert_called_once()

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_valid_token_no_refresh(self, mock_model, mock_login_user, plugin_setup):
        """Test valid (non-expired) JWT token does not trigger refresh"""
        # Mock model.User.by_name to avoid database queries
        mock_user = MagicMock()
        mock_model.User.by_name.return_value = mock_user

        # Setup valid token scenario - JWT disabled so check_token_expiration is not called
        plugin_setup.oauth2helper.jwt_enable = False
        plugin_setup.oauth2helper.identify = MagicMock(return_value=('testuser', MagicMock()))
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value={'access_token': 'new_token'})
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=None)

        # Set authorization header with valid token
        plugin.toolkit.request.headers = {OAUTH2_AUTHORIZATION_HEADER: 'Bearer valid_token'}
        plugin.toolkit.g.user = None
        plugin.g.user = None

        # Call identify
        plugin_setup.identify()

        # Verify refresh was NOT called (because identify succeeded, no ExpiredSignatureError)
        plugin_setup.oauth2helper.refresh_token.assert_not_called()
        assert plugin.toolkit.g.user is not None

    @patch('ckanext.oauth2.plugin.login_user')
    def test_identify_x_tapis_token_invalid_returns_401(self, mock_login_user, plugin_setup):
        """X-Tapis-Token with invalid token must return 401, not anonymous"""
        self._set_identity(None)
        plugin_setup.oauth2helper.identify = MagicMock(side_effect=ValueError('Invalid Key'))
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=None)

        plugin.toolkit.request.headers = {'X-Tapis-Token': 'bad_token'}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None

        plugin_setup.identify()

        plugin.toolkit.abort.assert_called_once_with(401, 'Invalid or expired X-Tapis-Token')

    @patch('ckanext.oauth2.plugin.login_user')
    def test_identify_x_tapis_token_expired_returns_401(self, mock_login_user, plugin_setup):
        """X-Tapis-Token with expired token and no refresh must return 401"""
        self._set_identity(None)
        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.jwt_username_field = 'tapis/username'
        plugin_setup.oauth2helper.identify = MagicMock(side_effect=jwt.ExpiredSignatureError("Token expired"))
        plugin_setup.oauth2helper._decode_jwt = MagicMock(return_value={'tapis/username': 'testuser'})
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=None)
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=None)

        plugin.toolkit.request.headers = {'X-Tapis-Token': 'expired_token'}
        plugin.toolkit.g.user = None
        plugin.g.user = None

        plugin_setup.identify()

        plugin.toolkit.abort.assert_called_once_with(401, 'Invalid or expired X-Tapis-Token')

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_authorization_header_priority_over_x_tapis_token(self, mock_model, mock_login_user, plugin_setup):
        """When both headers present, Authorization: Bearer is used, X-Tapis-Token ignored"""
        mock_model.User.by_name.return_value = MagicMock()
        self._set_identity(None)

        plugin_setup.oauth2helper.identify = MagicMock(return_value=('bearer_user', MagicMock()))
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=None)
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(False, None))

        plugin.toolkit.request.headers = {
            OAUTH2_AUTHORIZATION_HEADER: 'Bearer good_token',
            'X-Tapis-Token': 'other_token'
        }
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.g.user = None

        plugin_setup.identify()

        # Verify identify was called with the Bearer token, not the X-Tapis-Token
        plugin_setup.oauth2helper.identify.assert_called_once_with({'access_token': 'good_token'})
        assert plugin.toolkit.g.user == 'bearer_user'

    # -------------------------------------------------------------------------
    # Tests for identify() early-return guard (session path, no auth header)
    # -------------------------------------------------------------------------

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_skips_jwt_when_session_only(self, mock_model, mock_login_user, plugin_setup):
        """Early-return guard fires when session is authenticated and NO auth header present.

        Verifies g.* is populated correctly and oauth2helper.identify is NOT called
        (no JWT decode happens in the session-only path).
        """
        mock_model.User.by_name.return_value = MagicMock()
        self._set_identity('preauthed_user')

        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value={'access_token': 'stored_token'})
        plugin_setup.oauth2helper.jwt_enable = False  # no expiration check
        plugin_setup.oauth2helper.identify = MagicMock()

        plugin.toolkit.request.headers = {}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.toolkit.g.usertoken_refresh = None

        plugin_setup.identify()

        assert plugin.toolkit.g.user == 'preauthed_user'
        assert plugin.toolkit.g.usertoken == {'access_token': 'stored_token'}
        assert plugin.toolkit.g.usertoken_refresh is not None
        assert callable(plugin.toolkit.g.usertoken_refresh)
        # Key assertion: no JWT decode happened
        plugin_setup.oauth2helper.identify.assert_not_called()

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_early_return_sets_usertoken_refresh(self, mock_model, mock_login_user, plugin_setup):
        """g.usertoken_refresh is callable and invokes refresh_token when called."""
        mock_model.User.by_name.return_value = MagicMock()
        self._set_identity('preauthed_user')

        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value={'access_token': 'stored_token'})
        plugin_setup.oauth2helper.jwt_enable = False
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value={'access_token': 'refreshed_token'})

        plugin.toolkit.request.headers = {}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.toolkit.g.usertoken_refresh = None

        plugin_setup.identify()

        assert plugin.toolkit.g.usertoken_refresh is not None
        plugin.toolkit.g.usertoken_refresh()
        plugin_setup.oauth2helper.refresh_token.assert_called_once_with('preauthed_user')

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_early_return_refreshes_expired_stored_token(self, mock_model, mock_login_user, plugin_setup):
        """Early-return path refreshes an expired stored token."""
        mock_model.User.by_name.return_value = MagicMock()
        self._set_identity('testuser')

        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value={'access_token': 'expired_stored'})
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(True, 'testuser'))
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value={'access_token': 'new_token'})

        plugin.toolkit.request.headers = {}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None

        plugin_setup.identify()

        assert plugin.toolkit.g.usertoken == {'access_token': 'new_token'}
        plugin_setup.oauth2helper.refresh_token.assert_called_once_with('testuser')

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.logout_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_early_return_logout_on_refresh_failure(self, mock_model, mock_logout, mock_login_user, plugin_setup):
        """Early-return path logs out user when stored token refresh fails."""
        mock_model.User.by_name.return_value = MagicMock()
        self._set_identity('testuser')

        plugin_setup.oauth2helper.jwt_enable = True
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value={'access_token': 'expired_stored'})
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(True, 'testuser'))
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=None)

        plugin.toolkit.request.headers = {}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None

        plugin_setup.identify()

        assert plugin.toolkit.g.user is None
        assert plugin.toolkit.g.usertoken is None
        mock_logout.assert_called_once()

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_bearer_token_beats_session_identity(self, mock_model, mock_login_user, plugin_setup):
        """When bearer token header AND session identity are both present, bearer wins.

        Verifies the early-return guard does NOT fire when apikey is present,
        so the full JWT validation path runs and bearer token identity prevails.
        """
        mock_model.User.by_name.return_value = MagicMock()
        self._set_identity('session_user')

        mock_bearer_user_obj = MagicMock()
        plugin_setup.oauth2helper.identify = MagicMock(return_value=('bearer_user', mock_bearer_user_obj))
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value={'access_token': 'tok'})
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(False, None))

        plugin.toolkit.request.headers = {OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.toolkit.g.usertoken_refresh = None

        plugin_setup.identify()

        assert plugin.toolkit.g.user == 'bearer_user'  # NOT 'session_user'
        plugin_setup.oauth2helper.identify.assert_called_once()

    @patch('ckanext.oauth2.plugin.login_user')
    @patch('ckanext.oauth2.plugin.model')
    def test_identify_bearer_token_not_invalidated_by_stale_stored_token(self, mock_model, mock_login_user, plugin_setup):
        """Bearer token auth must not be undone by an expired stored token.

        When a valid bearer token authenticates the user, the stored token
        expiration check should be skipped. Otherwise a stale stored token
        causes the user to be logged out despite sending a valid fresh token.
        """
        mock_model.User.by_name.return_value = MagicMock()

        mock_user_obj = MagicMock()
        plugin_setup.oauth2helper.identify = MagicMock(return_value=('wmobley', mock_user_obj))
        plugin_setup.oauth2helper.jwt_enable = True
        # Stored token is expired, refresh would fail
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value={'access_token': 'old_expired_token'})
        plugin_setup.oauth2helper.check_token_expiration = MagicMock(return_value=(True, 'wmobley'))
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=None)

        plugin.toolkit.request.headers = {'X-Tapis-Token': 'fresh_valid_token'}
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.toolkit.g.usertoken_refresh = None

        plugin_setup.identify()

        # User must remain authenticated despite stale stored token
        assert plugin.toolkit.g.user == 'wmobley'
        # check_token_expiration should NOT have been called (skipped for bearer auth)
        plugin_setup.oauth2helper.check_token_expiration.assert_not_called()

    # -------------------------------------------------------------------------
    # Tests for _install_request_loader()
    # -------------------------------------------------------------------------

    def test_install_request_loader_registers_callback(self, plugin_setup):
        """_install_request_loader calls login_manager.request_loader with a callable."""
        mock_login_manager = MagicMock()
        registered_callbacks = []
        mock_login_manager.request_loader = MagicMock(side_effect=lambda f: registered_callbacks.append(f) or f)
        mock_current_app = MagicMock()
        mock_current_app.login_manager = mock_login_manager

        mock_get_apitoken = MagicMock(return_value=None)

        with patch('flask.current_app', mock_current_app):
            with patch('ckan.views._get_user_for_apitoken', mock_get_apitoken):
                plugin_setup._install_request_loader()

        mock_login_manager.request_loader.assert_called_once()
        registered_fn = mock_login_manager.request_loader.call_args[0][0]
        assert callable(registered_fn)

    @patch('ckanext.oauth2.plugin.model')
    def test_request_loader_returns_user_for_valid_bearer(self, mock_model, plugin_setup):
        """request_loader callback returns model.User for a valid Bearer token."""
        mock_user_obj = MagicMock()
        plugin_setup.oauth2helper.identify = MagicMock(return_value=('testuser', mock_user_obj))

        mock_login_manager = MagicMock()
        mock_login_manager.request_loader = MagicMock(side_effect=lambda f: f)
        mock_current_app = MagicMock()
        mock_current_app.login_manager = mock_login_manager

        mock_get_apitoken = MagicMock(return_value=None)

        with patch('flask.current_app', mock_current_app):
            with patch('ckan.views._get_user_for_apitoken', mock_get_apitoken):
                plugin_setup._install_request_loader()

        registered_callback = mock_login_manager.request_loader.call_args[0][0]

        mock_request = MagicMock()
        mock_request.headers = {plugin_setup.authorization_header: 'Bearer valid_token'}

        result = registered_callback(mock_request)

        assert result == mock_user_obj
        plugin_setup.oauth2helper.identify.assert_called_once_with({'access_token': 'valid_token'})

    @patch('ckanext.oauth2.plugin.model')
    def test_request_loader_falls_back_on_identify_exception(self, mock_model, plugin_setup):
        """request_loader callback falls back to _get_user_for_apitoken (not abort) when identify raises."""
        plugin_setup.oauth2helper.identify = MagicMock(side_effect=ValueError('Invalid'))

        mock_login_manager = MagicMock()
        mock_login_manager.request_loader = MagicMock(side_effect=lambda f: f)
        mock_current_app = MagicMock()
        mock_current_app.login_manager = mock_login_manager

        mock_get_apitoken = MagicMock(return_value=None)

        with patch('flask.current_app', mock_current_app):
            with patch('ckan.views._get_user_for_apitoken', mock_get_apitoken):
                plugin_setup._install_request_loader()

        registered_callback = mock_login_manager.request_loader.call_args[0][0]

        mock_request = MagicMock()
        mock_request.headers = {plugin_setup.authorization_header: 'Bearer bad_token'}

        result = registered_callback(mock_request)

        assert result is None

    @patch('ckanext.oauth2.plugin.model')
    def test_request_loader_falls_back_to_apitoken(self, mock_model, plugin_setup):
        """request_loader callback falls back to _get_user_for_apitoken when no OAuth2 headers."""
        plugin_setup.oauth2helper.identify = MagicMock()

        mock_login_manager = MagicMock()
        mock_login_manager.request_loader = MagicMock(side_effect=lambda f: f)
        mock_current_app = MagicMock()
        mock_current_app.login_manager = mock_login_manager

        mock_native_user = MagicMock()
        mock_get_apitoken = MagicMock(return_value=mock_native_user)

        with patch('flask.current_app', mock_current_app):
            with patch('ckan.views._get_user_for_apitoken', mock_get_apitoken):
                plugin_setup._install_request_loader()

        registered_callback = mock_login_manager.request_loader.call_args[0][0]

        mock_request = MagicMock()
        mock_request.headers = {}  # no OAuth2 headers

        result = registered_callback(mock_request)

        assert result == mock_native_user
        plugin_setup.oauth2helper.identify.assert_not_called()
        mock_get_apitoken.assert_called_once()

    def test_install_request_loader_logs_error_on_import_failure(self, plugin_setup):
        """_install_request_loader logs ERROR and raises when _get_user_for_apitoken cannot be imported."""
        mock_current_app = MagicMock()
        mock_current_app.login_manager = MagicMock()

        # Make the import of ckan.views._get_user_for_apitoken fail
        original_modules = sys.modules.copy()
        sys.modules['ckan.views'] = None  # causes ImportError on `from ckan.views import ...`

        try:
            with patch('flask.current_app', mock_current_app):
                with pytest.raises(ImportError):
                    plugin_setup._install_request_loader()
        finally:
            sys.modules.update(original_modules)

        # request_loader_installed must remain False since install failed
        assert plugin_setup._request_loader_installed is False
