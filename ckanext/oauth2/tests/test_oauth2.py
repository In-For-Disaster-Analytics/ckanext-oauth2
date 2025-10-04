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

        helper = OAuth2Helper()

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

    @patch('ckanext.oauth2.oauth2.OAuth2Session')
    def test_get_token_legacy_idm(self, OAuth2Session, oauth2_setup):
        helper = self._helper(oauth2_setup)
        helper.legacy_idm = True
        helper.verify_https = True
        OAuth2Session().fetch_token.return_value = OAUTH2TOKEN

        state = b64encode(json.dumps({'came_from': 'initial-page'}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})
        retrieved_token = helper.get_token()

        expected_headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic %s' % urlsafe_b64encode(
                ('%s:%s' % (helper.client_id, helper.client_secret)).encode('utf-8')
            ).decode('utf-8')
        }

        OAuth2Session().fetch_token.assert_called_once_with(
            helper.token_endpoint,
            headers=expected_headers,
            client_secret=helper.client_secret,
            authorization_response=oauth2.toolkit.request.url,
            verify=True
        )
        assert retrieved_token == OAUTH2TOKEN

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

    @pytest.mark.parametrize("headers", [
        {},
        [('Set-Cookie', 'cookie1="cookie1val"; Path=/')],
        [('Set-Cookie', 'cookie1="cookie1val"; Path=/'), ('Set-Cookie', 'cookie12="cookie2val"; Path=/')],
    ])
    @patch('ckanext.oauth2.oauth2.jsonify')
    def test_remember(self, mock_jsonify, oauth2_setup, headers):
        user_name = 'user_name'

        # Configure the mocks
        mock_response = MagicMock()
        mock_jsonify.return_value = mock_response

        environ = MagicMock()
        plugins = MagicMock()
        authenticator = MagicMock()
        authenticator.remember = MagicMock(return_value=headers)

        environ.get = MagicMock(return_value=plugins)
        oauth2.toolkit.request.environ = environ
        plugins.get = MagicMock(return_value=authenticator)

        # Call the function
        helper = self._helper(oauth2_setup)
        result = helper.remember(user_name)

        # Check that the remember method has been called properly
        authenticator.remember.assert_called_once_with(environ, {'repoze.who.userid': user_name})

        for header, value in headers:
            mock_response.headers.__setitem__.assert_any_call(header, value)

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
        returned_username = helper.identify(OAUTH2TOKEN)

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
        returned_username = helper.identify(OAUTH2TOKEN)

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
        returned_username = helper.identify(OAUTH2TOKEN)

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
        returned_username = helper.identify(OAUTH2TOKEN)

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
        user_data = {'tapis/username': 'test_user', 'tapis/email': 'test@test.com'}

        oauth2.jwt.decode.return_value = user_data

        oauth2.model.Session = MagicMock()
        user = MagicMock()
        user.name = 'test_user'
        user.email = 'test@test.com'
        oauth2.model.User = MagicMock(return_value=user)
        oauth2.model.User.by_name = MagicMock(return_value=user)

        returned_username = helper.identify(token)

        assert 'test_user' == returned_username

        oauth2.model.Session.add.assert_called_once_with(user)
        oauth2.model.Session.commit.assert_called_once()
        oauth2.model.Session.remove.assert_called_once()

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

    @patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
    def test_identify_invalid_cert_legacy(self, oauth2_setup):

        helper = self._helper(oauth2_setup, conf={"ckan.oauth2.legacy_idm": "True"})
        token = {'access_token': 'OAUTH_TOKEN'}

        with pytest.raises(InsecureTransportError):
            with patch('ckanext.oauth2.oauth2.requests.get') as requests_get_mock:
                requests_get_mock.side_effect = SSLError('(Caused by SSLError(SSLError("bad handshake: Error([(\'SSL routines\', \'tls_process_server_certificate\', \'certificate verify failed\')],)",),)')
                helper.identify(token)

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
    def test_redirect_from_callback(self, oauth2_setup, identity):
        came_from = 'initial-page'
        state = b64encode(json.dumps({'came_from': came_from}).encode('utf-8'))
        oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})

        helper = self._helper(oauth2_setup)
        resp_remember = MagicMock()
        resp_remember.headers = []
        helper.redirect_from_callback(resp_remember)

        assert oauth2.toolkit.response.status == 302
        assert oauth2.toolkit.response.location == came_from

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
