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
from urllib import urlencode

import ckanext.oauth2.oauth2 as oauth2
from ckanext.oauth2.oauth2 import OAuth2Helper
import httpretty
from unittest.mock import patch, MagicMock
from oauthlib.oauth2 import InsecureTransportError, MissingCodeError, MissingTokenError
from requests.exceptions import SSLError

OAUTH2TOKEN = {
    'access_token': 'token',
    'token_type': 'Bearer',
    'expires_in': '3600',
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
def oauth2_helper():
    """Create and configure OAuth2Helper instance"""
    # Save original values
    _toolkit = oauth2.toolkit
    _User = oauth2.model.User
    _Session = oauth2.model.Session
    _db = oauth2.db
    _OAuth2Session = oauth2.OAuth2Session

    # Mock toolkit and other dependencies
    oauth2.toolkit = MagicMock()
    oauth2.db = MagicMock()
    oauth2.jwt = MagicMock()

    # Configure OAuth2 settings
    oauth2.toolkit.config = {
        'ckan.oauth2.legacy_idm': 'false',
        'ckan.oauth2.authorization_endpoint': 'https://test/oauth2/authorize/',
        'ckan.oauth2.token_endpoint': 'https://test/oauth2/token/',
        'ckan.oauth2.client_id': 'client-id',
        'ckan.oauth2.client_secret': 'client-secret',
        'ckan.oauth2.profile_api_url': 'https://test/oauth2/user',
        'ckan.oauth2.profile_api_user_field': 'nickName',
        'ckan.oauth2.profile_api_mail_field': 'mail',
    }

    helper = OAuth2Helper()
    helper.profile_api_fullname_field = 'fullname'

    yield helper

    # Restore original values
    oauth2.toolkit = _toolkit
    oauth2.model.User = _User
    oauth2.model.Session = _Session
    oauth2.db = _db
    oauth2.OAuth2Session = _OAuth2Session

@pytest.mark.parametrize('conf_to_remove', [
    "ckan.oauth2.authorization_endpoint",
    "ckan.oauth2.token_endpoint",
    "ckan.oauth2.client_id",
    "ckan.oauth2.client_secret",
    "ckan.oauth2.profile_api_url",
    "ckan.oauth2.profile_api_user_field",
    "ckan.oauth2.profile_api_mail_field",
])
def test_minimum_conf(conf_to_remove):
    """Test that missing required configuration raises ValueError"""
    oauth2.toolkit = MagicMock()
    oauth2.toolkit.config = {
        'ckan.oauth2.legacy_idm': 'false',
        'ckan.oauth2.authorization_endpoint': 'https://test/oauth2/authorize/',
        'ckan.oauth2.token_endpoint': 'https://test/oauth2/token/',
        'ckan.oauth2.client_id': 'client-id',
        'ckan.oauth2.client_secret': 'client-secret',
        'ckan.oauth2.profile_api_url': 'https://test/oauth2/user',
        'ckan.oauth2.profile_api_user_field': 'nickName',
        'ckan.oauth2.profile_api_mail_field': 'mail',
    }
    del oauth2.toolkit.config[conf_to_remove]

    with pytest.raises(ValueError):
        OAuth2Helper()

@patch('ckanext.oauth2.oauth2.OAuth2Session')
def test_get_token_with_no_credentials(oauth2_session_mock, oauth2_helper):
    """Test get_token with missing code parameter"""
    state = b64encode(json.dumps({'came_from': 'initial-page'}))
    oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state})

    oauth2_session_mock().fetch_token.side_effect = MissingCodeError("Missing code parameter in response.")
    with pytest.raises(MissingCodeError):
        oauth2_helper.get_token()

@patch('ckanext.oauth2.oauth2.OAuth2Session')
@patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
def test_get_token(OAuth2Session, oauth2_helper):
    """Test successful token retrieval"""
    token = OAUTH2TOKEN
    OAuth2Session().fetch_token.return_value = OAUTH2TOKEN

    state = b64encode(json.dumps({'came_from': 'initial-page'}))
    oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})
    retrieved_token = oauth2_helper.get_token()

    for key in token:
        assert key in retrieved_token
        assert token[key] == retrieved_token[key]

@patch('ckanext.oauth2.oauth2.OAuth2Session')
def test_get_token_legacy_idm(OAuth2Session, oauth2_helper):
    """Test token retrieval with legacy IDM"""
    oauth2_helper.legacy_idm = True
    oauth2_helper.verify_https = True
    OAuth2Session().fetch_token.return_value = OAUTH2TOKEN

    state = b64encode(json.dumps({'came_from': 'initial-page'}))
    oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})
    retrieved_token = oauth2_helper.get_token()

    expected_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic %s' % urlsafe_b64encode(
            '%s:%s' % (oauth2_helper.client_id, oauth2_helper.client_secret)
        )
    }

    OAuth2Session().fetch_token.assert_called_once_with(
        oauth2_helper.token_endpoint,
        headers=expected_headers,
        client_secret=oauth2_helper.client_secret,
        authorization_response=oauth2.toolkit.request.url,
        verify=True
    )
    assert retrieved_token == OAUTH2TOKEN

@httpretty.activate
@patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
def test_get_token_insecure(oauth2_helper):
    """Test token retrieval with insecure transport"""
    token = OAUTH2TOKEN
    httpretty.register_uri(httpretty.POST, oauth2_helper.token_endpoint, body=json.dumps(token))

    state = b64encode(json.dumps({'came_from': 'initial-page'}))
    oauth2.toolkit.request = make_request(False, 'data.com', 'callback', {'state': state, 'code': 'code'})

    with pytest.raises(InsecureTransportError):
        oauth2_helper.get_token()

@httpretty.activate
@patch.dict(os.environ, {'OAUTHLIB_INSECURE_TRANSPORT': ''})
def test_get_token_invalid_cert(oauth2_helper):
    """Test token retrieval with invalid certificate"""
    token = OAUTH2TOKEN
    httpretty.register_uri(httpretty.POST, oauth2_helper.token_endpoint, body=json.dumps(token))

    state = b64encode(json.dumps({'came_from': 'initial-page'}))
    oauth2.toolkit.request = make_request(True, 'data.com', 'callback', {'state': state, 'code': 'code'})

    with pytest.raises(SSLError):
        oauth2_helper.get_token()

# Continue converting the remaining tests...
