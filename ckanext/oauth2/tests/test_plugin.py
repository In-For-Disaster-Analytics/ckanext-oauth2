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

CUSTOM_AUTHORIZATION_HEADER = 'x-auth-token'
OAUTH2_AUTHORIZATION_HEADER = 'authorization'
HOST = 'ckan.theme.org'


@pytest.fixture
def plugin_setup():
    # Save functions and mock them
    original_toolkit = plugin.toolkit
    plugin.toolkit = MagicMock()
    plugin.toolkit.config = {'ckan.oauth2.authorization_header': OAUTH2_AUTHORIZATION_HEADER}

    original_oauth2 = plugin.oauth2
    plugin.oauth2 = MagicMock()

    # Create the plugin
    oauth2_plugin = plugin.OAuth2Plugin()
    oauth2_plugin.update_config(plugin.toolkit.config)
    
    yield oauth2_plugin
    
    # Cleanup
    plugin.toolkit = original_toolkit
    plugin.oauth2 = original_oauth2


class TestPlugin:

    def _set_identity(self, identity):
        plugin.toolkit.request.environ = {}
        if identity:
            plugin.toolkit.request.environ['repoze.who.identity'] = {'repoze.who.userid': identity}

    @pytest.mark.parametrize("register_url,reset_url,edit_url", [
        (None, None, None),
        ('a', None, None),
        (None, 'a', None),
        (None, None, 'a'),
        ('a', 'b', 'c')
    ])
    def test_before_map(self, plugin_setup, register_url, reset_url, edit_url):

        # Setup the config dictionary
        plugin.toolkit.config = {}

        if register_url:
            plugin.toolkit.config['ckan.oauth2.register_url'] = register_url

        if reset_url:
            plugin.toolkit.config['ckan.oauth2.reset_url'] = reset_url

        if edit_url:
            plugin.toolkit.config['ckan.oauth2.edit_url'] = edit_url

        plugin_setup.update_config(plugin.toolkit.config)

        # In this case we need a own instance of the plugin, so we create it
        oauth2_plugin = plugin.OAuth2Plugin()

        # Create the mapper (mock) and call the function
        mapper = MagicMock()
        oauth2_plugin.before_map(mapper)

        # Check that the mapper has been called correctly
        mapper.connect.assert_called_with('/oauth2/callback',
                                          controller='ckanext.oauth2.controller:OAuth2Controller',
                                          action='callback')

        if register_url:
            mapper.redirect.assert_any_call('/user/register', register_url)

        if reset_url:
            mapper.redirect.assert_any_call('/user/reset', reset_url)

        if edit_url:
            mapper.redirect.assert_any_call('/user/edit/{user}', edit_url)

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

    ])
    @patch("ckanext.oauth2.plugin.g")
    def test_identify(self, plugin_setup, headers, authenticate_result, identity, expected_user, oauth2, g_mock):

        if not oauth2:
            plugin.toolkit.config = {'ckan.oauth2.authorization_header': CUSTOM_AUTHORIZATION_HEADER}
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
            else:
                return authenticate_result

        plugin_setup.oauth2helper.identify = MagicMock(side_effect=authenticate_side_effect)
        plugin_setup.oauth2helper.get_stored_token = MagicMock(return_value=usertoken)
        plugin_setup.oauth2helper.refresh_token = MagicMock(return_value=newtoken)

        # Authentication header is not included
        plugin.toolkit.request.headers = headers

        # The identify function must set the user id in this variable
        plugin.toolkit.g.user = None
        plugin.toolkit.g.usertoken = None
        plugin.toolkit.g.usertoken_refresh = None

        # Call the function
        plugin_setup.identify()

        # Check that the function "authenticate" (called when the API Key is included) has not been called
        if oauth2 and OAUTH2_AUTHORIZATION_HEADER in headers and headers[OAUTH2_AUTHORIZATION_HEADER].startswith('Bearer '):
            token = headers[OAUTH2_AUTHORIZATION_HEADER].replace('Bearer ', '')
            plugin_setup.oauth2helper.identify.assert_called_once_with({'access_token': token})
        elif not oauth2 and CUSTOM_AUTHORIZATION_HEADER in headers:
            plugin_setup.oauth2helper.identify.assert_called_once_with({'access_token': headers[CUSTOM_AUTHORIZATION_HEADER]})
        else:
            assert plugin_setup.oauth2helper.identify.call_count == 0

        assert expected_user == g_mock.user
        assert expected_user == plugin.toolkit.g.user

        if expected_user is None:
            assert plugin.toolkit.g.usertoken is None
            assert plugin.toolkit.g.usertoken_refresh is None
        else:
            assert usertoken == plugin.toolkit.g.usertoken

            # method 'usertoken_refresh' should relay on the one provided by the repoze.who module
            plugin.toolkit.g.usertoken_refresh()
            plugin_setup.oauth2helper.refresh_token.assert_called_once_with(expected_user)
            assert newtoken == plugin.toolkit.g.usertoken
