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

from __future__ import print_function, unicode_literals

from base64 import b64encode, urlsafe_b64encode
import json
import os
import pytest
from urllib.parse import urlencode

import ckanext.oauth2.oauth2 as oauth2
from ckanext.oauth2.oauth2 import OAuth2Helper
import httpretty
from unittest.mock import patch, MagicMock
from oauthlib.oauth2 import InsecureTransportError, MissingCodeError, MissingTokenError
from requests.exceptions import SSLError

OAUTH2TOKEN = {
    'access_token': 'token',
    'token_type': 'Bearer',
    'expires_in': 3600,
    'refresh_token': 'refresh_token',
}


def make_request(secure, host, path, params):
    request = MagicMock()

    # Generate the string of paramaters1
    params_str = ''
    for param in params:
        params_str += '%s=%s&' % (param, params[param])

    secure = 's' if secure else ''
    request.url = 'http%s://%s/%s?%s' % (secure, host, path, params_str)
    request.host = host
    request.host_url = 'http%s://%s' % (secure, host)
    request.params = params
    request.args = params  # Support both deprecated params and new args
    return request


@pytest.fixture
def oauth2_setup():
    user_field = 'nickName'
    fullname_field = 'fullname'
    email_field = 'mail'
    profile_api_url = 'https://test/oauth2/user'
    group_field = 'groups'

    # Get the functions that can be mocked and affect other tests
    original_toolkit = oauth2.toolkit
    original_User = oauth2.model.User
    original_Session = oauth2.model.Session
    original_db = oauth2.db
    original_OAuth2Session = oauth2.OAuth2Session

    # Mock toolkit
    oauth2.toolkit = MagicMock()

    yield {
        'user_field': user_field,
        'fullname_field': fullname_field,
        'email_field': email_field,
        'profile_api_url': profile_api_url,
        'group_field': group_field
    }

    # Reset the functions
    oauth2.toolkit = original_toolkit
    oauth2.model.User = original_User
    oauth2.model.Session = original_Session
    oauth2.db = original_db
    oauth2.OAuth2Session = original_OAuth2Session


class TestOAuth2Plugin:

    def _helper(self, oauth2_setup, fullname_field=True, mail_field=True, conf=None, missing_conf=None, jwt_enable=False):
        oauth2.db = MagicMock()
        oauth2.jwt = MagicMock()

        oauth2.toolkit.config = {
            'ckan.oauth2.legacy_idm': 'false',
            'ckan.oauth2.authorization_endpoint': 'https://test/oauth2/authorize/',
            'ckan.oauth2.token_endpoint': 'https://test/oauth2/token/',
            'ckan.oauth2.client_id': 'client-id',
            'ckan.oauth2.client_secret': 'client-secret',
            'ckan.oauth2.profile_api_url': oauth2_setup['profile_api_url'],
            'ckan.oauth2.profile_api_user_field': oauth2_setup['user_field'],
            'ckan.oauth2.profile_api_mail_field': oauth2_setup['email_field'],
        }
        if conf is not None:
            oauth2.toolkit.config.update(conf)
        if missing_conf is not None:
            del oauth2.toolkit.config[missing_conf]

        helper = OAuth2Helper(oauth2.toolkit.config)

        if fullname_field:
            helper.profile_api_fullname_field = oauth2_setup['fullname_field']

        if jwt_enable:
            helper.jwt_enable = True
            helper.jwt_algorithm = 'HS256'
            helper.jwt_secret = 'test-secret'

        return helper

    @pytest.mark.parametrize("conf_to_remove", [
        "ckan.oauth2.authorization_endpoint",
        "ckan.oauth2.token_endpoint",
        "ckan.oauth2.client_id",
        "ckan.oauth2.client_secret",
        "ckan.oauth2.profile_api_url",
        "ckan.oauth2.profile_api_user_field",
        "ckan.oauth2.profile_api_mail_field",
    ])
    def test_minimum_conf(self, oauth2_setup, conf_to_remove):
        with pytest.raises(ValueError):
            self._helper(oauth2_setup, missing_conf=conf_to_remove)

    @patch('ckanext.oauth2.oauth2.OAuth2Session')
    def test_get_token_with_no_credentials(self, oauth2_session_mock, oauth2_setup):
        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state})

        helper = self._helper(oauth2_setup)

        oauth2_session_mock().fetch_token.side_effect = MissingCodeError("Missing code parameter in response.")
        with pytest.raises(MissingCodeError):
            helper.get_token()

    @patch('ckanext.oauth2.oauth2.OAuth2Session')
    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_get_token(self, OAuth2Session, oauth2_setup):
        helper = self._helper(oauth2_setup)
        token = OAUTH2TOKEN
        OAuth2Session().fetch_token.return_value = OAUTH2TOKEN

        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})
        retrieved_token = helper.get_token()

        for key, value in token.items():
            assert key in retrieved_token
            assert value == retrieved_token[key]

    # @patch('ckanext.oauth2.oauth2.OAuth2Session')
    # def test_get_token_legacy_idm(self, OAuth2Session, oauth2_setup):
    #     helper = self._helper(oauth2_setup)
    #     helper.legacy_idm = True
    #     helper.verify_https = True
    #     OAuth2Session().fetch_token.return_value = OAUTH2TOKEN

    #     state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
    #     oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})
    #     retrieved_token = helper.get_token()

    #     expected_headers = {
    #         'Accept': 'application/json',
    #         'Content-Type': 'application/x-www-form-urlencoded',
    #         'Authorization': 'Basic %s' % urlsafe_b64encode(
    #             ('%s:%s' % (helper.client_id, helper.client_secret)).encode('utf-8')
    #         ).decode('utf-8')
    #     }

    #     OAuth2Session().fetch_token.assert_called_once_with(
    #         helper.token_endpoint,
    #         headers=expected_headers,
    #         client_secret=helper.client_secret,
    #         authorization_response=oauth2.toolkit.request.url,
    #         verify=True
    #     )
    #     assert retrieved_token == OAUTH2TOKEN

    @httpretty.activate
    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_get_token_insecure(self, oauth2_setup):
        helper = self._helper(oauth2_setup)
        token = OAUTH2TOKEN
        httpretty.register_uri(httpretty.POST, helper.token_endpoint, body=json.dumps(token))

        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(False, 'data.com', 'callback', {'state': state, 'code': 'code'})

        with pytest.raises(InsecureTransportError):
            helper.get_token()

    @httpretty.activate
    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_get_token_invalid_cert(self, oauth2_setup):
        helper = self._helper(oauth2_setup)
        token = OAUTH2TOKEN
        httpretty.register_uri(httpretty.POST, helper.token_endpoint, body=json.dumps(token))

        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})

        with pytest.raises(InsecureTransportError):
            with patch('ckanext.oauth2.oauth2.OAuth2Session') as oauth2_session_mock:
                oauth2_session_mock().fetch_token.side_effect = SSLError('(Caused by SSLError(SSLError("bad handshake: Error([(\'SSL routines\', \'tls_process_server_certificate\', \'certificate verify failed\')],)",),)')
                helper.get_token()

    @httpretty.activate
    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_get_token_unexpected_ssl_error(self, oauth2_setup):
        helper = self._helper(oauth2_setup)
        token = OAUTH2TOKEN
        httpretty.register_uri(httpretty.POST, helper.token_endpoint, body=json.dumps(token))

        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})

        with pytest.raises(SSLError):
            with patch('ckanext.oauth2.oauth2.OAuth2Session') as oauth2_session_mock:
                oauth2_session_mock().fetch_token.side_effect = SSLError('unexpected error')
                helper.get_token()

    @httpretty.activate
    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': 'True'})
    def test_get_token_insecure_enabled(self, oauth2_setup):
        """Test that OAuth2Helper can retrieve access tokens over HTTP when insecure transport is enabled.

        This test verifies the token exchange works in development/testing environments where HTTPS
        isn't available. The OAUTHLIB_INSECURE_TRANSPORT environment variable bypasses OAuth2's
        default HTTPS enforcement.
        """
        helper = self._helper(oauth2_setup)
        token = OAUTH2TOKEN
        httpretty.register_uri(httpretty.POST, helper.token_endpoint, body=json.dumps(token))

        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(False, 'data.com', 'callback', {'state': state, 'code': 'code'})
        retrieved_token = helper.get_token()

        for key, value in token.items():
            assert key in retrieved_token
            assert value == retrieved_token[key]

    @httpretty.activate
    def test_get_token_error(self, oauth2_setup):
        helper = self._helper(oauth2_setup)
        token = {
            'info': 'auth_error',
            'error_description': 'Some description'
        }
        httpretty.register_uri(httpretty.POST, helper.token_endpoint, body=json.dumps(token))

        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})

        with pytest.raises(MissingTokenError):
            helper.get_token()

    def test_challenge(self, oauth2_setup):
        helper = self._helper(oauth2_setup)

        # Build mocks
        request = MagicMock()
        request = make_request(False, 'localhost', 'user/login', {})
        request.environ = MagicMock()
        request.headers = {}
        came_from = '/came_from_theme'

        oauth2.toolkit.request = request

        # Call the method
        helper.challenge(came_from)

        # Check
        state = urlencode({'state': b64encode(json.dumps({'came_from': came_from}).encode('utf-8'))})
        expected_url = 'https://test/oauth2/authorize/?response_type=code&client_id=client-id&' + \
                       'redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Foauth2%2Fcallback&' + state
        oauth2.toolkit.redirect_to.assert_called_once_with(expected_url)

    @pytest.mark.parametrize("username,fullname,email,fullname_field", [
        ('test_user', 'Test User Full Name', 'test@test.com', True),
        ('test_user', None, 'test@test.com', True),
        ('test_user', 'Test User Full Name', 'test@test.com', False),
    ])
    @httpretty.activate
    def test_identify_user_exists_no_sysadmin(self, oauth2_setup, username, fullname, email, fullname_field):
        """
        Test identify when user already exists in the database (no sysadmin check).

        When a user already exists, identify() should:
        - Find the user by username using User.by_name()
        - Return the existing user without modification
        - Not create a new user object
        """
        helper = self._helper(oauth2_setup, fullname_field)

        # Simulate OAuth provider response
        user_info = {
            oauth2_setup['user_field']: username,
            oauth2_setup['email_field']: email
        }
        if fullname:
            user_info[oauth2_setup['fullname_field']] = fullname

        httpretty.register_uri(httpretty.GET, oauth2_setup['profile_api_url'], body=json.dumps(user_info))

        # Mock the request and database
        request = make_request(False, 'localhost', '/oauth2/callback', {})
        oauth2.toolkit.request = request
        oauth2.model.Session = MagicMock()

        # Create existing user mock
        user = MagicMock()
        user.name = username
        user.email = email

        oauth2.model.User = MagicMock(return_value=user)
        oauth2.model.User.by_name = MagicMock(return_value=user)
        oauth2.model.User.by_email = MagicMock(return_value=[user])

        # Call identify
        returned_username, returned_user = helper.identify(OAUTH2TOKEN)

        # Verify the user was found and returned
        assert returned_username == username
        oauth2.model.User.by_name.assert_called_once_with(username)
        oauth2.model.User.by_email.assert_not_called()

        # Verify no new user was created
        assert oauth2.model.User.called == 0

        # Verify session operations
        oauth2.model.Session.add.assert_called_once_with(user)
        oauth2.model.Session.commit.assert_called_once()
        oauth2.model.Session.remove.assert_called_once()

    @pytest.mark.parametrize("username,fullname,email,fullname_field", [
        ('test_user', 'Test User Full Name', 'test@test.com', True),
        ('test_user', None, 'test@test.com', True),
        ('test_user', None, 'test@test.com', False),
    ])
    @httpretty.activate
    def test_identify_user_not_exists_no_sysadmin(self, oauth2_setup, username, fullname, email, fullname_field):
        """
        Test identify when user does not exist in the database (no sysadmin check).

        When a user doesn't exist, identify() should:
        - Try to find by username first (returns None)
        - Try to find by email (returns empty list)
        - Create a new user with properties from OAuth provider
        - Set fullname only if provided and fullname_field is configured
        """
        helper = self._helper(oauth2_setup, fullname_field)

        # Simulate OAuth provider response
        user_info = {
            oauth2_setup['user_field']: username,
            oauth2_setup['email_field']: email
        }
        if fullname:
            user_info[oauth2_setup['fullname_field']] = fullname

        httpretty.register_uri(httpretty.GET, oauth2_setup['profile_api_url'], body=json.dumps(user_info))

        # Mock the request and database
        request = make_request(False, 'localhost', '/oauth2/callback', {})
        oauth2.toolkit.request = request
        oauth2.model.Session = MagicMock()

        # Create new user mock
        user = MagicMock()
        user.name = username
        user.email = email

        oauth2.model.User = MagicMock(return_value=user)
        oauth2.model.User.by_name = MagicMock(return_value=None)
        oauth2.model.User.by_email = MagicMock(return_value=[])

        # Call identify
        returned_username, returned_user = helper.identify(OAUTH2TOKEN)

        # Verify the user was created
        assert returned_username == username
        oauth2.model.User.assert_called_once_with(name=username, email=email)

        # Verify user properties
        assert user.name == username
        assert user.email == email

        # Verify session operations
        oauth2.model.Session.add.assert_called_once_with(user)
        oauth2.model.Session.commit.assert_called_once()
        oauth2.model.Session.remove.assert_called_once()

    @pytest.mark.parametrize("sysadmin", [True, False])
    @httpretty.activate
    def test_identify_user_exists_with_sysadmin(self, oauth2_setup, sysadmin):
        """
        Test identify when user already exists with sysadmin group check.

        When a user already exists, identify() should:
        - Find the user by username
        - Return the existing user without modifying sysadmin status
        """
        username = 'test_user'
        email = 'test@test.com'
        helper = self._helper(oauth2_setup, fullname_field=True)
        helper.profile_api_groupmembership_field = oauth2_setup['group_field']
        helper.sysadmin_group_name = "admin"

        # Simulate OAuth provider response with group membership
        user_info = {
            oauth2_setup['user_field']: username,
            oauth2_setup['email_field']: email,
            oauth2_setup['group_field']: "admin" if sysadmin else "other"
        }

        httpretty.register_uri(httpretty.GET, oauth2_setup['profile_api_url'], body=json.dumps(user_info))

        # Mock the request and database
        request = make_request(False, 'localhost', '/oauth2/callback', {})
        oauth2.toolkit.request = request
        oauth2.model.Session = MagicMock()

        # Create existing user mock
        user = MagicMock()
        user.name = username
        user.email = email

        oauth2.model.User = MagicMock(return_value=user)
        oauth2.model.User.by_name = MagicMock(return_value=user)
        oauth2.model.User.by_email = MagicMock(return_value=[user])

        # Call identify
        returned_username, returned_user = helper.identify(OAUTH2TOKEN)

        # Verify the user was found and returned
        assert returned_username == username
        oauth2.model.User.by_name.assert_called_once_with(username)

        # Verify no new user was created
        assert oauth2.model.User.called == 0

        # Verify session operations
        oauth2.model.Session.add.assert_called_once_with(user)
        oauth2.model.Session.commit.assert_called_once()
        oauth2.model.Session.remove.assert_called_once()

    @pytest.mark.parametrize("sysadmin", [True, False])
    @httpretty.activate
    def test_identify_user_not_exists_with_sysadmin(self, oauth2_setup, sysadmin):
        """
        Test identify when user does not exist with sysadmin group check.

        When a user doesn't exist, identify() should:
        - Create a new user with properties from OAuth provider
        - Set sysadmin status based on group membership
        """
        username = 'test_user'
        email = 'test@test.com'
        helper = self._helper(oauth2_setup, fullname_field=True)
        helper.profile_api_groupmembership_field = oauth2_setup['group_field']
        helper.sysadmin_group_name = "admin"

        # Simulate OAuth provider response with group membership
        user_info = {
            oauth2_setup['user_field']: username,
            oauth2_setup['email_field']: email,
            oauth2_setup['group_field']: "admin" if sysadmin else "other"
        }

        httpretty.register_uri(httpretty.GET, oauth2_setup['profile_api_url'], body=json.dumps(user_info))

        # Mock the request and database
        request = make_request(False, 'localhost', '/oauth2/callback', {})
        oauth2.toolkit.request = request
        oauth2.model.Session = MagicMock()

        # Create new user mock
        user = MagicMock()
        user.name = username
        user.email = email

        oauth2.model.User = MagicMock(return_value=user)
        oauth2.model.User.by_name = MagicMock(return_value=None)
        oauth2.model.User.by_email = MagicMock(return_value=[])

        # Call identify
        returned_username, returned_user = helper.identify(OAUTH2TOKEN)

        # Verify the user was created
        assert returned_username == username
        oauth2.model.User.assert_called_once_with(name=username, email=email)

        # Verify sysadmin status was set correctly
        assert user.sysadmin == sysadmin

        # Verify session operations
        oauth2.model.Session.add.assert_called_once_with(user)
        oauth2.model.Session.commit.assert_called_once()
        oauth2.model.Session.remove.assert_called_once()

    def test_identify_jwt(self, oauth2_setup):

        helper = self._helper(oauth2_setup, jwt_enable=True)
        token = OAUTH2TOKEN
        user_data = {'username': 'test_user', 'email': 'test@test.com'}

        oauth2.jwt.decode.return_value = user_data

        oauth2.model.Session = MagicMock()
        user = MagicMock()
        user.name = 'test_user'
        user.email = 'test@test.com'
        oauth2.model.User = MagicMock(return_value=user)
        oauth2.model.User.by_name = MagicMock(return_value=user)

        returned_username, returned_user = helper.identify(token)

        assert 'test_user' == returned_username

        oauth2.model.Session.add.assert_called_once_with(user)
        oauth2.model.Session.commit.assert_called_once()
        oauth2.model.Session.remove.assert_called_once()

    def test_identify_jwt_with_tapis_fields(self, oauth2_setup):
        """Test JWT identification with Tapis-style namespaced fields"""
        helper = self._helper(oauth2_setup, jwt_enable=True)
        # Configure JWT field names for Tapis
        helper.jwt_username_field = 'tapis/username'
        helper.jwt_email_field = 'tapis/email'

        token = OAUTH2TOKEN
        user_data = {'tapis/username': 'tapis_user', 'tapis/email': 'tapis@test.com'}

        oauth2.jwt.decode.return_value = user_data

        oauth2.model.Session = MagicMock()
        user = MagicMock()
        user.name = 'tapis_user'
        user.email = 'tapis@test.com'
        oauth2.model.User = MagicMock(return_value=user)
        oauth2.model.User.by_name = MagicMock(return_value=user)

        returned_username, returned_user = helper.identify(token)

        assert 'tapis_user' == returned_username

        oauth2.model.Session.add.assert_called_once_with(user)
        oauth2.model.Session.commit.assert_called_once()
        oauth2.model.Session.remove.assert_called_once()

    def test_identify_jwt_username_only_profile_provides_all(self, oauth2_setup):
        """Test JWT with only username, profile API provides all data - user doesn't exist"""
        helper = self._helper(oauth2_setup, jwt_enable=True)
        token = OAUTH2TOKEN

        # JWT only has username
        jwt_data = {'username': 'test_user'}
        oauth2.jwt.decode.return_value = jwt_data

        # Profile API has all data
        profile_data = {
            oauth2_setup['user_field']: 'test_user',
            oauth2_setup['email_field']: 'test@example.com',
            oauth2_setup['fullname_field']: 'Test User'
        }

        # Mock profile API response
        with patch('ckanext.oauth2.oauth2.OAuth2Helper.query_profile_api_default') as mock_profile:
            mock_response = MagicMock()
            mock_response.json.return_value = profile_data
            mock_profile.return_value = mock_response

            oauth2.model.Session = MagicMock()
            user = MagicMock()
            user.name = 'test_user'
            user.email = 'test@example.com'
            user.fullname = 'Test User'
            oauth2.model.User = MagicMock(return_value=user)
            # User doesn't exist - find_user should raise ValueError
            oauth2.model.User.by_name = MagicMock(return_value=None)
            oauth2.model.User.by_email = MagicMock(return_value=[])

            returned_username, returned_user = helper.identify(token)

            assert 'test_user' == returned_username
            # Profile API should have been called to get complementary data
            mock_profile.assert_called_once()

    def test_identify_jwt_username_only_profile_fails(self, oauth2_setup):
        """Test JWT with only username, profile API fails - user doesn't exist"""
        helper = self._helper(oauth2_setup, jwt_enable=True)
        token = OAUTH2TOKEN

        # JWT only has username
        jwt_data = {'username': 'test_user'}
        oauth2.jwt.decode.return_value = jwt_data

        # Mock profile API to fail
        with patch('ckanext.oauth2.oauth2.OAuth2Helper.query_profile_api_default') as mock_profile:
            mock_profile.side_effect = Exception("Profile API unavailable")

            oauth2.model.Session = MagicMock()
            user = MagicMock()
            user.name = 'test_user'
            user.email = None
            oauth2.model.User = MagicMock(return_value=user)
            # User doesn't exist
            oauth2.model.User.by_name = MagicMock(return_value=None)
            oauth2.model.User.by_email = MagicMock(return_value=[])

            returned_username, returned_user = helper.identify(token)

            # Should still work with JWT data only
            assert 'test_user' == returned_username
            mock_profile.assert_called_once()

    def test_identify_jwt_username_only_profile_all_data_username_match(self, oauth2_setup):
        """Test JWT with username, profile API with all data where usernames match - user doesn't exist"""
        helper = self._helper(oauth2_setup, jwt_enable=True)
        token = OAUTH2TOKEN

        # JWT has username
        jwt_data = {'username': 'test_user'}
        oauth2.jwt.decode.return_value = jwt_data

        # Profile API has all data with matching username
        profile_data = {
            oauth2_setup['user_field']: 'test_user',  # Same username
            oauth2_setup['email_field']: 'test@example.com',
            oauth2_setup['fullname_field']: 'Test User'
        }

        with patch('ckanext.oauth2.oauth2.OAuth2Helper.query_profile_api_default') as mock_profile:
            mock_response = MagicMock()
            mock_response.json.return_value = profile_data
            mock_profile.return_value = mock_response

            oauth2.model.Session = MagicMock()
            user = MagicMock()
            user.name = 'test_user'
            user.email = 'test@example.com'
            user.fullname = 'Test User'
            oauth2.model.User = MagicMock(return_value=user)
            oauth2.model.User.by_name = MagicMock(return_value=None)
            oauth2.model.User.by_email = MagicMock(return_value=[])

            returned_username, returned_user = helper.identify(token)

            assert 'test_user' == returned_username
            # Verify user was created with merged data
            oauth2.model.Session.add.assert_called_once_with(user)

    def test_identify_jwt_username_only_profile_all_data_username_differs(self, oauth2_setup):
        """Test JWT with username, profile API with different username - JWT takes priority"""
        helper = self._helper(oauth2_setup, jwt_enable=True)
        token = OAUTH2TOKEN

        # JWT has username
        jwt_data = {'username': 'jwt_user'}
        oauth2.jwt.decode.return_value = jwt_data

        # Profile API has all data with DIFFERENT username
        profile_data = {
            oauth2_setup['user_field']: 'profile_user',  # Different username
            oauth2_setup['email_field']: 'test@example.com',
            oauth2_setup['fullname_field']: 'Test User'
        }

        with patch('ckanext.oauth2.oauth2.OAuth2Helper.query_profile_api_default') as mock_profile:
            mock_response = MagicMock()
            mock_response.json.return_value = profile_data
            mock_profile.return_value = mock_response

            oauth2.model.Session = MagicMock()
            user = MagicMock()
            user.name = 'jwt_user'  # JWT username should win
            user.email = 'test@example.com'  # Email from profile API
            user.fullname = 'Test User'  # Fullname from profile API
            oauth2.model.User = MagicMock(return_value=user)
            oauth2.model.User.by_name = MagicMock(return_value=None)
            oauth2.model.User.by_email = MagicMock(return_value=[])

            returned_username, returned_user = helper.identify(token)

            # JWT username should be used, not profile username
            assert 'jwt_user' == returned_username
            oauth2.model.Session.add.assert_called_once_with(user)

    @httpretty.activate
    def test_identify_profile_api_field_mismatch(self, oauth2_setup):
        """Test that missing required fields in profile API response causes failure"""
        helper = self._helper(oauth2_setup, jwt_enable=False)
        token = OAUTH2TOKEN

        # Profile API response uses 'tapis/username' but we're configured to look for 'username'
        # This should fail because the configured field names don't match the response
        profile_data = {
            'tapis/username': 'test_user',  # Wrong field name
            'tapis/email': 'test@example.com',  # Wrong field name
            'tapis/fullname': 'Test User'  # Wrong field name
        }

        httpretty.register_uri(
            httpretty.GET,
            oauth2_setup['profile_api_url'],
            body=json.dumps(profile_data)
        )

        oauth2.model.Session = MagicMock()
        oauth2.model.User.by_name = MagicMock(return_value=None)
        oauth2.model.User.by_email = MagicMock(return_value=[])

        # This should raise ValueError because username/email are not found
        with pytest.raises(ValueError, match="Username or email is required"):
            helper.identify(token)

    @pytest.mark.parametrize("user_info", [
        {'error': 'invalid_token', 'error_description': 'Error Description'},
        {'error': 'another_error'},
    ])
    @httpretty.activate
    def test_identify_invalid_token(self, oauth2_setup, user_info):

        helper = self._helper(oauth2_setup)
        token = {'access_token': 'OAUTH_TOKEN'}

        httpretty.register_uri(httpretty.GET, helper.profile_api_url, status=401, body=json.dumps(user_info))

        exception_risen = False
        try:
            helper.identify(token)
        except Exception as e:
            if user_info['error'] == 'invalid_token':
                assert isinstance(e, ValueError)
                assert user_info['error_description'] == str(e)
            exception_risen = True

        assert exception_risen

    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_identify_invalid_cert(self, oauth2_setup):

        helper = self._helper(oauth2_setup)
        token = {'access_token': 'OAUTH_TOKEN'}

        with pytest.raises(SSLError):
            with patch('ckanext.oauth2.oauth2.requests.get') as requests_get_mock:
                requests_get_mock.side_effect = SSLError('(Caused by SSLError(SSLError("bad handshake: Error([(\'SSL routines\', \'tls_process_server_certificate\', \'certificate verify failed\')],)",),)')
                helper.identify(token)

    # @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    # def test_identify_invalid_cert_legacy(self, oauth2_setup):

    #     helper = self._helper(oauth2_setup, conf={"ckan.oauth2.legacy_idm": "True"})
    #     token = {'access_token': 'OAUTH_TOKEN'}

    #     with pytest.raises(InsecureTransportError):
    #         with patch('ckanext.oauth2.oauth2.requests.get') as requests_get_mock:
    #             requests_get_mock.side_effect = SSLError('(Caused by SSLError(SSLError("bad handshake: Error([(\'SSL routines\', \'tls_process_server_certificate\', \'certificate verify failed\')],)",),)')
    #             helper.identify(token)

    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_identify_unexpected_ssl_error(self, oauth2_setup):

        helper = self._helper(oauth2_setup)
        token = {'access_token': 'OAUTH_TOKEN'}

        with pytest.raises(SSLError):
            with patch('requests.get') as requests_get_mock:
                requests_get_mock.side_effect = SSLError('unexpected error')
                helper.identify(token)

    def test_get_stored_token_non_existing_user(self, oauth2_setup):
        helper = self._helper(oauth2_setup)
        oauth2.db.UserToken.by_user_name = MagicMock(return_value=None)
        assert helper.get_stored_token('user') is None

    def test_get_stored_token_existing_user(self, oauth2_setup):
        helper = self._helper(oauth2_setup)

        usertoken = MagicMock()
        usertoken.access_token = OAUTH2TOKEN['access_token']
        usertoken.token_type = OAUTH2TOKEN['token_type']
        usertoken.expires_in = OAUTH2TOKEN['expires_in']
        usertoken.refresh_token = OAUTH2TOKEN['refresh_token']

        oauth2.db.UserToken.by_user_name = MagicMock(return_value=usertoken)
        assert OAUTH2TOKEN == helper.get_stored_token('user')

    @pytest.mark.parametrize("identity", [
        {'came_from': 'http://localhost/dataset'},
        {},
    ])
    @patch('ckanext.oauth2.oauth2.jsonify')
    def test_redirect_from_callback(self, mock_jsonify, oauth2_setup, identity):
        came_from = 'initial-page'
        state = b64encode(json.dumps({'came_from': came_from}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})

        # Configure the mock
        mock_response = MagicMock()
        mock_jsonify.return_value = mock_response

        helper = self._helper(oauth2_setup)
        resp_remember = MagicMock()
        # Mock headers to behave like Flask Headers object
        mock_headers = MagicMock()
        mock_headers.keys.return_value = []
        mock_headers.getlist.return_value = []
        resp_remember.headers = mock_headers
        result = helper.redirect_from_callback(resp_remember)

        assert mock_response.status_code == 302
        mock_response.headers.__setitem__.assert_any_call('location', came_from)

    @pytest.mark.parametrize("user_exists,jwt_expires_in", [
        (True, True),
        (True, False),
        (False, False),
        (False, True),
    ])
    def test_update_token(self, oauth2_setup, user_exists, jwt_expires_in):
        helper = self._helper(oauth2_setup, jwt_enable=not jwt_expires_in)
        user = 'user'

        if user_exists:
            usertoken = MagicMock()
            usertoken.user_name = user
            usertoken.access_token = OAUTH2TOKEN['access_token']
            usertoken.token_type = OAUTH2TOKEN['token_type']
            usertoken.expires_in = OAUTH2TOKEN['expires_in']
            usertoken.refresh_token = OAUTH2TOKEN['refresh_token']
        else:
            usertoken = None
            oauth2.db.UserToken = MagicMock()

        oauth2.model.Session = MagicMock()
        oauth2.db.UserToken.by_user_name = MagicMock(return_value=usertoken)

        # The token to be updated
        if jwt_expires_in:
            newtoken = {
                'access_token': 'new_access_token',
                'token_type': 'new_token_type',
                'expires_in': 'new_expires_in',
                'refresh_token': 'new_refresh_token'
            }
            helper.update_token('user', newtoken)

            # Check that the object has been stored
            oauth2.model.Session.add.assert_called_once()
            oauth2.model.Session.commit.assert_called_once()

            # Check that the object contains the correct information
            tk = oauth2.model.Session.add.call_args_list[0][0][0]
            assert tk.user_name == user
            assert tk.access_token == newtoken['access_token']
            assert tk.token_type == newtoken['token_type']
            assert tk.expires_in == newtoken['expires_in']
            assert tk.refresh_token == newtoken['refresh_token']
        else:
            newtoken = {
                'access_token': 'new_access_token',
                'token_type': 'new_token_type',
                'refresh_token': 'new_refresh_token'
            }
            expires_in_data = {'exp': 3600, 'iat': 0}
            oauth2.jwt.decode.return_value = expires_in_data
            helper.update_token('user', newtoken)

            # Check that the object has been stored
            oauth2.model.Session.add.assert_called_once()
            oauth2.model.Session.commit.assert_called_once()

            # Check that the object contains the correct information
            tk = oauth2.model.Session.add.call_args_list[0][0][0]
            assert tk.user_name == user
            assert tk.access_token == newtoken['access_token']
            assert tk.token_type == newtoken['token_type']
            assert tk.expires_in == 3600
            assert tk.refresh_token == newtoken['refresh_token']


    @pytest.mark.parametrize("user_exists", [
        True,
        False,
    ])
    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': '', 'REQUESTS_CA_BUNDLE': ''})
    def test_refresh_token(self, oauth2_setup, user_exists):
        username = 'user'
        helper = self.helper = self._helper(oauth2_setup)

        # mock get_token
        if user_exists:
            current_token = OAUTH2TOKEN
        else:
            current_token = None

        # mock plugin functions
        helper.get_stored_token = MagicMock(return_value=current_token)
        helper.update_token = MagicMock()

        # The token returned by the system
        newtoken = {
            'access_token': 'new_access_token',
            'token_type': 'new_token_type',
            'expires_in': 'new_expires_in',
            'refresh_token': 'new_refresh_token'
        }
        session = MagicMock()
        session.refresh_token = MagicMock(return_value=newtoken)
        oauth2.OAuth2Session = MagicMock(return_value=session)

        # Call the function
        result = helper.refresh_token(username)

        if user_exists:
            assert result == newtoken
            helper.get_stored_token.assert_called_once_with(username)
            oauth2.OAuth2Session.assert_called_once_with(helper.client_id, token=current_token, scope=helper.scope)
            session.refresh_token.assert_called_once_with(helper.token_endpoint, client_secret=helper.client_secret, client_id=helper.client_id, verify=True)
            helper.update_token.assert_called_once_with(username, newtoken)
        else:
            assert result is None
            assert oauth2.OAuth2Session.call_count == 0
            assert session.refresh_token.call_count == 0
            assert helper.update_token.call_count == 0

    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_refresh_token_invalid_cert(self, oauth2_setup):
        username = 'user'
        current_token = OAUTH2TOKEN
        helper = self._helper(oauth2_setup)

        # mock plugin functions
        helper.get_stored_token = MagicMock(return_value=current_token)

        with pytest.raises(InsecureTransportError):
            with patch('ckanext.oauth2.oauth2.OAuth2Session') as oauth2_session_mock:
                oauth2_session_mock().refresh_token.side_effect = SSLError('(Caused by SSLError(SSLError("bad handshake: Error([(\'SSL routines\', \'tls_process_server_certificate\', \'certificate verify failed\')],)",),)')
                helper.refresh_token(username)

    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_refresh_token_unexpected_ssl_error(self, oauth2_setup):
        username = 'user'
        current_token = OAUTH2TOKEN
        helper = self._helper(oauth2_setup)

        # mock plugin functions
        helper.get_stored_token = MagicMock(return_value=current_token)

        with pytest.raises(SSLError):
            with patch('ckanext.oauth2.oauth2.OAuth2Session') as oauth2_session_mock:
                oauth2_session_mock().refresh_token.side_effect = SSLError('unexpected error')
                helper.refresh_token(username)

    def test_create_user_object_with_username_and_email(self, oauth2_setup):
        """Test creating user with both username and email"""
        helper = self._helper(oauth2_setup)
        user_profile = {
            oauth2_setup['user_field']: 'testuser',
            oauth2_setup['email_field']: 'test@example.com'
        }

        user = helper.create_user_object(user_profile)

        assert user.name == 'testuser'
        assert user.email == 'test@example.com'

    def test_create_user_object_with_username_only(self, oauth2_setup):
        """Test creating user with only username"""
        helper = self._helper(oauth2_setup)
        user_profile = {
            oauth2_setup['user_field']: 'testuser'
        }

        user = helper.create_user_object(user_profile)

        assert user.name == 'testuser'
        assert user.email is None

    def test_create_user_object_with_email_only(self, oauth2_setup):
        """Test creating user with only email"""
        helper = self._helper(oauth2_setup)
        user_profile = {
            oauth2_setup['email_field']: 'test@example.com'
        }

        user = helper.create_user_object(user_profile)

        assert user.name is None
        assert user.email == 'test@example.com'

    def test_create_user_object_missing_both_username_and_email(self, oauth2_setup):
        """Test that creating user without username or email raises error"""
        helper = self._helper(oauth2_setup)
        user_profile = {}

        with pytest.raises(ValueError) as exc_info:
            helper.create_user_object(user_profile)

        assert "Username or email is required" in str(exc_info.value)

    def test_create_user_object_with_fullname(self, oauth2_setup):
        """Test creating user with fullname field"""
        helper = self._helper(oauth2_setup, fullname_field=True)
        user_profile = {
            oauth2_setup['user_field']: 'testuser',
            oauth2_setup['email_field']: 'test@example.com',
            oauth2_setup['fullname_field']: 'Test User'
        }

        user = helper.create_user_object(user_profile)

        assert user.name == 'testuser'
        assert user.email == 'test@example.com'
        assert user.fullname == 'Test User'

    def test_create_user_object_with_firstname_lastname(self, oauth2_setup):
        """Test creating user with firstname and lastname fields"""
        helper = self._helper(oauth2_setup, fullname_field=False)
        helper.profile_api_firstname_field = 'first_name'
        helper.profile_api_lastname_field = 'last_name'

        user_profile = {
            oauth2_setup['user_field']: 'testuser',
            oauth2_setup['email_field']: 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User'
        }

        user = helper.create_user_object(user_profile)

        assert user.name == 'testuser'
        assert user.email == 'test@example.com'
        assert user.fullname == 'Test User'

    def test_create_user_object_with_tapis_fields(self, oauth2_setup):
        """Test creating user with Tapis-style JWT fields"""
        helper = self._helper(oauth2_setup)
        # Configure JWT field names for Tapis
        helper.jwt_username_field = 'tapis/username'
        helper.jwt_email_field = 'tapis/email'

        # Create user profile as if extracted from JWT token
        user_profile = {
            oauth2_setup['user_field']: 'tapisuser',
            oauth2_setup['email_field']: 'tapis@example.com'
        }

        user = helper.create_user_object(user_profile)

        assert user.name == 'tapisuser'
        assert user.email == 'tapis@example.com'

    def test_create_user_object_with_nested_jwt_fields(self, oauth2_setup):
        """Test creating user with nested JWT fields like 'tapis/username'"""
        helper = self._helper(oauth2_setup)

        # Simulate JWT token with nested fields being mapped to standard fields
        user_profile = {
            oauth2_setup['user_field']: 'nesteduser',
            oauth2_setup['email_field']: 'nested@example.com',
            oauth2_setup['fullname_field']: 'Nested User'
        }

        user = helper.create_user_object(user_profile)

        assert user.name == 'nesteduser'
        assert user.email == 'nested@example.com'
        assert user.fullname == 'Nested User'

    def test_unwrap_response_empty_path(self, oauth2_setup):
        """Empty path returns data unchanged"""
        helper = self._helper(oauth2_setup)
        data = {'foo': 'bar'}
        assert helper._unwrap_response(data, '') == data
        assert helper._unwrap_response(data, None) == data

    def test_unwrap_response_single_key(self, oauth2_setup):
        """Single key path unwraps one level"""
        helper = self._helper(oauth2_setup)
        data = {'result': {'username': 'test'}}
        assert helper._unwrap_response(data, 'result') == {'username': 'test'}

    def test_unwrap_response_nested_path(self, oauth2_setup):
        """Dot-separated path unwraps multiple levels"""
        helper = self._helper(oauth2_setup)
        data = {'response': {'data': {'username': 'test'}}}
        assert helper._unwrap_response(data, 'response.data') == {'username': 'test'}

    def test_unwrap_response_missing_key(self, oauth2_setup):
        """Missing key in path returns data as-is"""
        helper = self._helper(oauth2_setup)
        data = {'foo': 'bar'}
        assert helper._unwrap_response(data, 'nonexistent') == data

    def test_unwrap_response_partial_path(self, oauth2_setup):
        """Partially valid path returns data at point of failure"""
        helper = self._helper(oauth2_setup)
        data = {'result': {'foo': 'bar'}}
        assert helper._unwrap_response(data, 'result.nonexistent') == {'foo': 'bar'}

    def test_compliance_fix_with_token_response_path(self, oauth2_setup):
        """Token response unwrapping uses configured path and key"""
        helper = self._helper(oauth2_setup, conf={
            'ckan.oauth2.token_response_path': 'result',
            'ckan.oauth2.token_response_key': 'access_token',
        })

        mock_response = MagicMock()
        mock_response.json.return_value = {
            'result': {
                'access_token': {
                    'access_token': 'my_token',
                    'token_type': 'Bearer',
                }
            }
        }

        session = MagicMock()
        hooks = {}

        def register_hook(name, fn):
            hooks[name] = fn

        session.register_compliance_hook = register_hook
        helper._compliance_fix(session)

        result = hooks['access_token_response'](mock_response)
        content = json.loads(result._content.decode('utf-8'))
        assert content == {'access_token': 'my_token', 'token_type': 'Bearer'}

    @httpretty.activate
    def test_get_profile_from_api_with_path(self, oauth2_setup):
        """Profile API response is unwrapped using configured path"""
        helper = self._helper(oauth2_setup, conf={
            'ckan.oauth2.profile_response_path': 'result',
        })

        wrapped_response = {
            'result': {
                oauth2_setup['user_field']: 'testuser',
                oauth2_setup['email_field']: 'test@example.com',
            }
        }

        httpretty.register_uri(
            httpretty.GET,
            oauth2_setup['profile_api_url'],
            body=json.dumps(wrapped_response),
        )

        profile = helper.get_profile_from_api(OAUTH2TOKEN)
        assert profile[oauth2_setup['user_field']] == 'testuser'
        assert profile[oauth2_setup['email_field']] == 'test@example.com'

    @httpretty.activate
    def test_get_profile_from_api_without_path(self, oauth2_setup):
        """Profile API response returned as-is when no path configured"""
        helper = self._helper(oauth2_setup)

        flat_response = {
            oauth2_setup['user_field']: 'testuser',
            oauth2_setup['email_field']: 'test@example.com',
        }

        httpretty.register_uri(
            httpretty.GET,
            oauth2_setup['profile_api_url'],
            body=json.dumps(flat_response),
        )

        profile = helper.get_profile_from_api(OAUTH2TOKEN)
        assert profile[oauth2_setup['user_field']] == 'testuser'
        assert profile[oauth2_setup['email_field']] == 'test@example.com'

    def test_compliance_fix_without_token_response_path(self, oauth2_setup):
        """No unwrapping when token_response_path is empty"""
        helper = self._helper(oauth2_setup)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            'access_token': 'my_token',
            'token_type': 'Bearer',
        }

        session = MagicMock()
        hooks = {}

        def register_hook(name, fn):
            hooks[name] = fn

        session.register_compliance_hook = register_hook
        helper._compliance_fix(session)

        result = hooks['access_token_response'](mock_response)
        assert not hasattr(result._content, 'decode') or result._content == mock_response._content
