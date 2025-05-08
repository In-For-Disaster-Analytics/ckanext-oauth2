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

from base64 import b64decode, b64encode
import pytest
import json
from unittest.mock import MagicMock, patch
from ckanext.oauth2 import controller, plugin

RETURNED_STATUS = 302
EXAMPLE_FLASH = 'This is a test'
EXCEPTION_MSG = 'Invalid'
CAME_FROM_FIELD = 'came_from'

class CompleteException(Exception):
    description = 'Exception description'
    error = 'Exception error'

class ErrorException(Exception):
    error = 'Exception error 2'

class VoidException(Exception):
    pass

@pytest.fixture
def mock_controller(monkeypatch):
    """Mock controller dependencies"""
    # Mock helpers
    mock_helpers = MagicMock()
    monkeypatch.setattr(controller, 'helpers', mock_helpers)

    # Mock oauth2
    mock_oauth2 = MagicMock()
    monkeypatch.setattr(controller, 'oauth2', mock_oauth2)

    # Mock toolkit
    mock_toolkit = MagicMock()
    monkeypatch.setattr(controller, 'toolkit', mock_toolkit)
    monkeypatch.setattr(plugin, 'toolkit', mock_toolkit)

    # Mock session
    mock_session = MagicMock()
    monkeypatch.setattr(controller, 'session', mock_session)

    # Create controller instance
    controller_instance = controller.OAuth2Controller()
    return controller_instance

def generate_state(url):
    return b64encode(bytes(json.dumps({CAME_FROM_FIELD: url})))

def get_came_from(state):
    return json.loads(b64decode(state)).get(CAME_FROM_FIELD, '/')

def test_callback_no_errors(mock_controller):
    """Test callback with no errors"""
    oauth2Helper = controller.oauth2.OAuth2Helper.return_value

    token = 'TOKEN'
    user_id = 'user_id'
    oauth2Helper.get_token.return_value = token
    oauth2Helper.identify.return_value = user_id

    # Call the controller
    mock_controller.callback()

    oauth2Helper.get_token.assert_called_once()
    oauth2Helper.identify.assert_called_once_with(token)
    oauth2Helper.remember.assert_called_once_with(user_id)
    oauth2Helper.update_token.assert_called_once_with(user_id, token)
    oauth2Helper.redirect_from_callback.assert_called_once_with()

@pytest.mark.parametrize('came_from,exception,error_description,expected_flash', [
    (None, None, None, None),
    ('/', None, None, None),
    ('/', CompleteException(EXCEPTION_MSG), None, EXCEPTION_MSG),
    ('/', CompleteException(), None, CompleteException.description),
    ('/', ErrorException(EXCEPTION_MSG), None, EXCEPTION_MSG),
    ('/', ErrorException(), None, ErrorException.error),
    ('/', VoidException(EXCEPTION_MSG), None, EXCEPTION_MSG),
    ('/', VoidException(), None, type(VoidException()).__name__),
    ('/about', Exception(EXCEPTION_MSG), EXAMPLE_FLASH, EXAMPLE_FLASH)
])
def test_callback_errors(mock_controller, came_from, exception, error_description, expected_flash):
    """Test callback with various error scenarios"""
    # Recover function
    controller.oauth2.get_came_from = get_came_from

    oauth2Helper = controller.oauth2.OAuth2Helper.return_value
    oauth2Helper.get_token.side_effect = exception or Exception(EXCEPTION_MSG)

    controller.toolkit.request.GET = {}
    if came_from:
        controller.toolkit.request.GET['state'] = generate_state(came_from)
    if error_description is not None:
        controller.toolkit.request.GET['error_description'] = error_description
    controller.toolkit.request.params.get = controller.toolkit.request.GET.get

    # Call the controller
    mock_controller.callback()

    # Check the state and the location
    controller.session.save.assert_called_once_with()
    assert controller.toolkit.response.status_int == RETURNED_STATUS
    assert controller.toolkit.response.location == came_from
    if expected_flash:
        controller.helpers.flash_error.assert_called_once_with(expected_flash)

@pytest.mark.parametrize('referer,came_from,expected_referer', [
    (None, None, '/dashboard'),
    ('/about', None, '/about'),
    ('/about', '/ckan-admin', '/ckan-admin'),
    (None, '/ckan-admin', '/ckan-admin'),
    ('/', None, '/dashboard'),
    ('/user/logged_out_redirect', None, '/dashboard'),
    ('/', '/ckan-admin', '/ckan-admin'),
    ('/user/logged_out_redirect', '/ckan-admin', '/ckan-admin'),
    ('http://google.es', None, '/dashboard'),
    ('http://google.es', None, '/dashboard')
])
def test_login(mock_controller, referer, came_from, expected_referer):
    """Test login with various scenarios"""
    # The login function will check these variables
    controller.toolkit.request.headers = {}
    controller.toolkit.request.params = {}

    if referer:
        controller.toolkit.request.headers['Referer'] = referer

    if came_from:
        controller.toolkit.request.params['came_from'] = came_from

    # Call the function
    mock_controller.login()

    mock_controller.oauth2helper.challenge.assert_called_once_with(expected_referer)
