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

# from __future__ import unicode_literals

import logging
from .oauth2 import *
import os
import jwt

from functools import partial
from flask_login import current_user, login_user, logout_user
from ckan import plugins
from ckan.common import g
from ckan.plugins import toolkit
import ckan.model as model
import ckanext.oauth2.db as db
import urllib.parse
from ckanext.oauth2.views import get_blueprints
from ckanext.oauth2.cli import get_commands

log = logging.getLogger(__name__)


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


class _OAuth2Plugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IClick)

    # IBlueprint

    def get_blueprint(self):
        return get_blueprints()

    # IClick

    def get_commands(self):
        return get_commands()


class OAuth2Plugin(_OAuth2Plugin, plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    # plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)


    def __init__(self, name=None):
        '''Store the OAuth 2 client configuration'''
        log.debug('Init OAuth2 extension')
        self.name = name or 'oauth2'
        self.oauth2helper = None

    def get_helpers(self):
        return {
            'oauth2_get_stored_token': self.get_stored_token_helper,
            'oauth2_refresh_token': self.oauth2helper.refresh_token,
        }

    def get_stored_token_helper(self, user_name=None):
        """Template helper to get stored OAuth2 token for a user"""
        if not user_name:
            # Automatically get current user if no user_name provided
            user_name = getattr(toolkit.g, 'user', None)

        if not user_name:
            return None

        try:
            return self.oauth2helper.get_stored_token(user_name)
        except Exception as e:
            log.error(f"Error getting stored token for user {user_name}: {e}")
            return None

    def identify(self):
        log.debug('Starting identify process')

        def _refresh_and_save_token(user_name):
            log.debug(f'Refreshing token for user {user_name}')
            try:
                new_token = self.oauth2helper.refresh_token(user_name)
            except Exception as e:
                log.error(f'Token refresh failed for user {user_name}: {e}')
                new_token = None

            if new_token:
                toolkit.g.usertoken = new_token
                log.debug(f'Token refreshed for user {user_name}')
            else:
                log.warning(f'Token refresh unsuccessful for user {user_name}, logging out')
                toolkit.g.user = None
                toolkit.g.userobj = None
                toolkit.g.usertoken = None
                g.user = None
                logout_user()

        apikey = toolkit.request.headers.get(self.authorization_header, '')
        user_name = None
        user_obj = None

        if apikey:

            if apikey.startswith('Bearer '):
                apikey = apikey[7:].strip()
            try:
                token = {'access_token': apikey}
                user_name, user_obj = self.oauth2helper.identify(token)
                log.debug(f'Auth success: {user_name}')
            except jwt.ExpiredSignatureError:
                log.info('JWT token expired for API request, attempting refresh')
                try:
                    claims = self.oauth2helper._decode_jwt(apikey, verify=False)
                    expired_username = claims.get(self.oauth2helper.jwt_username_field)
                    if expired_username:
                        new_token = self.oauth2helper.refresh_token(expired_username)
                        if new_token:
                            user_name = expired_username
                            log.info('Token refreshed for user %s', expired_username)
                        else:
                            log.warning('Token refresh failed for user %s', expired_username)
                    else:
                        log.warning('Could not extract username from expired token')
                except Exception as e:
                    log.error('Error during token refresh: %s', e)
            except Exception as e:
                log.debug(f'Auth error: {e}')
                pass

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and current_user.is_authenticated:
            user_name = current_user.name
            log.info('User %s logged using session' % user_name)

        # If we have been able to log in the user (via API or Session)
        if user_name:
            g.user = user_name
            toolkit.g.user = user_name
            toolkit.g.userobj = user_obj if user_obj else model.User.by_name(user_name)
            toolkit.g.usertoken = self.oauth2helper.get_stored_token(user_name)

            # Set Flask-Login's current_user so CKAN 2.11 API views
            # (which use current_user.name for authorization) recognize
            # the authenticated user.
            login_user(toolkit.g.userobj)

            # Check if stored token is expired and refresh if needed
            if toolkit.g.usertoken and toolkit.g.usertoken.get('access_token') and self.oauth2helper.jwt_enable:
                is_expired, _ = self.oauth2helper.check_token_expiration(
                    toolkit.g.usertoken['access_token']
                )
                if is_expired:
                    log.info('Stored token expired for user %s, attempting refresh', user_name)
                    new_token = self.oauth2helper.refresh_token(user_name)
                    if new_token:
                        toolkit.g.usertoken = new_token
                        log.info('Stored token refreshed for user %s', user_name)
                    else:
                        log.warning('Stored token refresh failed for user %s, logging out', user_name)
                        toolkit.g.user = None
                        toolkit.g.userobj = None
                        toolkit.g.usertoken = None
                        g.user = None
                        logout_user()

            toolkit.g.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            g.user = None
            toolkit.g.user = None
            toolkit.g.userobj = None
            log.warning('The user is not currently logged...')

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset
        }

    def update_config(self, config):
        # Update our configuration
        log.debug('update config...')
        log.debug(f'Config values - site_url: {config.get("ckan.site_url")}, root_path: {config.get("ckan.root_path")}')

        # Initialize OAuth2Helper with the loaded config
        self.oauth2helper = OAuth2Helper(config)
        log.debug(f'OAuth2Helper initialized - redirect_uri: {self.oauth2helper.redirect_uri}')

        # Initialize database models (must be called after database engine is ready)
        db.init_db()

        self.register_url = os.environ.get("CKAN_OAUTH2_REGISTER_URL", config.get('ckan.oauth2.register_url', None))
        self.reset_url = os.environ.get("CKAN_OAUTH2_RESET_URL", config.get('ckan.oauth2.reset_url', None))
        self.edit_url = os.environ.get("CKAN_OAUTH2_EDIT_URL", config.get('ckan.oauth2.edit_url', None))
        self.authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", config.get('ckan.oauth2.authorization_header', 'Authorization')).lower()

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, 'templates')

