# -*- coding: utf-8 -*-

import logging
from flask import Blueprint, jsonify, make_response
import logging
from ckanext.oauth2 import constants
from ckanext.oauth2.oauth2 import get_came_from
from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.plugins.toolkit as toolkit
import urllib.parse
import ckan.plugins as plugins

log = logging.getLogger(__name__)
# service_proxy = Blueprint("service_proxy", __name__)
oauth2 = Blueprint("oauth2", __name__)

def _get_oauth2helper():
    """Get OAuth2Helper from the loaded plugin"""
    plugin = plugins.get_plugin('oauth2')
    return plugin.oauth2helper

def _get_previous_page(default_page):
    if 'came_from' not in toolkit.request.params:
        came_from_url = toolkit.request.headers.get('Referer', default_page)
    else:
        came_from_url = toolkit.request.params.get('came_from', default_page)

    came_from_url_parsed = urllib.parse.urlparse(came_from_url)

    # Ensure HTTPS scheme if the request is secure
    if toolkit.request.environ.get('HTTPS') == 'on' or toolkit.request.scheme == 'https':
        came_from_url = urllib.parse.urlunparse(
            ('https',) + came_from_url_parsed[1:]
        )
        came_from_url_parsed = urllib.parse.urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if came_from_url_parsed.netloc != '' and came_from_url_parsed.netloc != toolkit.request.host:
        came_from_url = default_page

    # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
    # he/she must be redirected to the dashboard
    pages = ['/', '/user/logged_out_redirect']
    if came_from_url_parsed.path in pages:
        came_from_url = default_page

    return came_from_url

@oauth2.route('/user/login')
def login():
    log.debug('login')
    came_from_url = _get_previous_page(constants.INITIAL_PAGE)
    return _get_oauth2helper().challenge(came_from_url)

@oauth2.route('/oauth2/callback')
def callback():
    try:
        oauth2helper = _get_oauth2helper()
        token = oauth2helper.get_token()
        user_name = oauth2helper.identify(token)
        response = oauth2helper.remember(user_name)
        log.debug(f'usr:{user_name}')
        oauth2helper.update_token(user_name, token)
        response = oauth2helper.redirect_from_callback(response)
    except Exception as e:
        # If the callback is called with an error, we must show the message
        error_description = toolkit.request.args.get('error_description')
        if not error_description:
            # Try to get error message from exception
            if hasattr(e, 'description') and e.description:
                error_description = e.description
            elif hasattr(e, 'error') and e.error:
                error_description = e.error
            elif str(e):
                error_description = str(e)
            else:
                error_description = type(e).__name__
        response = jsonify()
        response.status_code = 302
        redirect_url = get_came_from(toolkit.request.params.get('state'))
        redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
        response.location = redirect_url
        log.error(f'OAuth2 callback error: {error_description}')
        helpers.flash_error(error_description)
        # make_response((content, 302, headers))
    return response

def get_blueprints():
    return [oauth2]
