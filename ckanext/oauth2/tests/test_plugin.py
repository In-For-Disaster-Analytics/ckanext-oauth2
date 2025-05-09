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

import pytest
import ckanext.oauth2.plugin as plugin
from unittest.mock import MagicMock, patch
from parameterized import parameterized

CUSTOM_AUTHORIZATION_HEADER = 'x-auth-token'
OAUTH2_AUTHORIZATION_HEADER = 'authorization'
HOST = 'ckan.theme.org'

@pytest.fixture
def oauth2_plugin(mock_toolkit):
    """Create and return an OAuth2Plugin instance"""
    plugin.oauth2 = MagicMock()
    plugin_instance = plugin.OAuth2Plugin()
    plugin_instance.update_config(mock_toolkit.config)
    return plugin_instance

def test_before_map(oauth2_plugin, mock_toolkit):
    """Test the before_map method with various configurations"""
    # Setup the config dictionary
    mock_toolkit.config = {}

    # Test with no URLs configured
    mapper = MagicMock()
    oauth2_plugin.before_map(mapper)
    mapper.connect.assert_called_with('/oauth2/callback',
                                    controller='ckanext.oauth2.controller:OAuth2Controller',
                                    action='callback')
    assert not mapper.redirect.called

    # Test with register URL
    mock_toolkit.config['ckan.oauth2.register_url'] = 'register_url'
    oauth2_plugin.update_config(mock_toolkit.config)
    mapper = MagicMock()
    oauth2_plugin.before_map(mapper)
    mapper.redirect.assert_called_with('/user/register', 'register_url')

    # Test with reset URL
    mock_toolkit.config['ckan.oauth2.reset_url'] = 'reset_url'
    oauth2_plugin.update_config(mock_toolkit.config)
    mapper = MagicMock()
    oauth2_plugin.before_map(mapper)
    mapper.redirect.assert_called_with('/user/reset', 'reset_url')

    # Test with edit URL
    mock_toolkit.config['ckan.oauth2.edit_url'] = 'edit_url'
    oauth2_plugin.update_config(mock_toolkit.config)
    mapper = MagicMock()
    oauth2_plugin.before_map(mapper)
    mapper.redirect.assert_called_with('/user/edit/{user}', 'edit_url')

def test_auth_functions(oauth2_plugin):
    """Test the auth functions"""
    EXPECTED_AUTH_FUNCTIONS = ['user_create', 'user_update', 'user_reset', 'request_reset']
    auth_functions = oauth2_plugin.get_auth_functions()

    for auth_function in auth_functions:
        assert auth_function in EXPECTED_AUTH_FUNCTIONS
        function_result = auth_functions[auth_function]({'user': 'test'}, {})
        assert 'success' in function_result
        assert function_result['success'] is False

@pytest.mark.parametrize('headers,authenticate_result,identity,expected_user,oauth2', [
    ({}, None, None, None, False),
    ({}, None, None, None, True),
    ({}, None, 'test', 'test', False),
    ({}, None, 'test', 'test', True),
    ({'invalid_header': 'api_key'}, None, None, None, False),
    ({'invalid_header': 'api_key'}, None, 'test2', 'test2', False),
    ({'invalid_header': 'api_key'}, None, None, None, True),
    ({'invalid_header': 'api_key'}, None, 'test2', 'test2', True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, 'test', None, 'test', True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, 'test', 'test2', 'test', True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, ValueError('Invalid Key'), 'test2', 'test2', True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, ValueError('Invalid Key'), None, None, True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'Bearer api_key'}, None, 'test2', 'test2', True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'Otherr api_key'}, None, None, None, True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'api_key'}, None, 'test2', 'test2', True),
    ({OAUTH2_AUTHORIZATION_HEADER: 'api_key'}, None, None, None, True),
    ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'}, 'test', None, 'test', False),
    ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'}, 'test', 'test2', 'test', False),
    ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'}, ValueError('Invalid Key'), 'test2', 'test2', False),
    ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'}, ValueError('Invalid Key'), None, None, False),
    ({CUSTOM_AUTHORIZATION_HEADER: 'api_key'}, None, 'test2', 'test2', False),
])
@patch("ckanext.oauth2.plugin.g")
def test_identify(headers, authenticate_result, identity, expected_user, oauth2, g_mock, oauth2_plugin, mock_toolkit):
    """Test the identify method with various scenarios"""
    if not oauth2:
        mock_toolkit.config = {'ckan.oauth2.authorization_header': CUSTOM_AUTHORIZATION_HEADER}
        oauth2_plugin.update_config(mock_toolkit.config)

    # Set up identity
    mock_toolkit.request.environ = {}
    if identity:
        mock_toolkit.request.environ['repoze.who.identity'] = {'repoze.who.userid': identity}

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
        return authenticate_result

    oauth2_plugin.oauth2helper.identify = MagicMock(side_effect=authenticate_side_effect)
    oauth2_plugin.oauth2helper.get_stored_token = MagicMock(return_value=usertoken)
    oauth2_plugin.oauth2helper.refresh_token = MagicMock(return_value=newtoken)

    # Set up request headers
    mock_toolkit.request.headers = headers

    # Initialize g object
    mock_toolkit.g.user = None
    mock_toolkit.g.usertoken = None
    mock_toolkit.g.usertoken_refresh = None

    # Call the function
    oauth2_plugin.identify()

    # Verify the results
    if oauth2 and OAUTH2_AUTHORIZATION_HEADER in headers and headers[OAUTH2_AUTHORIZATION_HEADER].startswith('Bearer '):
        token = headers[OAUTH2_AUTHORIZATION_HEADER].replace('Bearer ', '')
        oauth2_plugin.oauth2helper.identify.assert_called_once_with({'access_token': token})
    elif not oauth2 and CUSTOM_AUTHORIZATION_HEADER in headers:
        oauth2_plugin.oauth2helper.identify.assert_called_once_with({'access_token': headers[CUSTOM_AUTHORIZATION_HEADER]})
    else:
        assert oauth2_plugin.oauth2helper.identify.call_count == 0

    assert g_mock.user == expected_user
    assert mock_toolkit.g.user == expected_user

    if expected_user is None:
        assert mock_toolkit.g.usertoken is None
        assert mock_toolkit.g.usertoken_refresh is None
    else:
        assert mock_toolkit.g.usertoken == usertoken
