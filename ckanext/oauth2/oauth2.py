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


import base64
import ckan.model as model
from ckanext.oauth2.db import UserToken
import ckanext.oauth2.db as db
import json
import logging
from six.moves.urllib.parse import urljoin
import os
from typing import Optional
from base64 import b64encode, b64decode
from ckan.plugins import toolkit
from oauthlib.oauth2 import InsecureTransportError
import requests
from requests_oauthlib import OAuth2Session
import six

import jwt

from .constants import *
from flask import Flask, request, redirect, session, url_for, jsonify



log = logging.getLogger(__name__)


def generate_state(url):
    return b64encode(bytes(json.dumps({CAME_FROM_FIELD: url}).encode()))


def get_came_from(state):
    return json.loads(b64decode(state)).get(CAME_FROM_FIELD, '/')


REQUIRED_CONF = ("authorization_endpoint", "token_endpoint", "client_id", "client_secret", "profile_api_url", "profile_api_user_field", "profile_api_mail_field")

class OAuth2Helper(object):

    def __init__(self):

        self.verify_https = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '') == ""
        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.jwt_enable = six.text_type(os.environ.get('CKAN_OAUTH2_JWT_ENABLE', toolkit.config.get('ckan.oauth2.jwt.enable',''))).strip().lower() in ("true", "1", "on")

        self.legacy_idm = six.text_type(os.environ.get('CKAN_OAUTH2_LEGACY_IDM', toolkit.config.get('ckan.oauth2.legacy_idm', ''))).strip().lower() in ("true", "1", "on")
        self.authorization_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_AUTHORIZATION_ENDPOINT', toolkit.config.get('ckan.oauth2.authorization_endpoint', ''))).strip()
        self.token_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_TOKEN_ENDPOINT', toolkit.config.get('ckan.oauth2.token_endpoint', ''))).strip()
        self.profile_api_url = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_URL', toolkit.config.get('ckan.oauth2.profile_api_url', ''))).strip()
        self.client_id = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_ID', toolkit.config.get('ckan.oauth2.client_id', ''))).strip()
        self.client_secret = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_SECRET', toolkit.config.get('ckan.oauth2.client_secret', ''))).strip()
        self.scope = six.text_type(os.environ.get('CKAN_OAUTH2_SCOPE', toolkit.config.get('ckan.oauth2.scope', ''))).strip()
        self.rememberer_name = six.text_type(os.environ.get('CKAN_OAUTH2_REMEMBER_NAME', toolkit.config.get('ckan.oauth2.rememberer_name', 'auth_tkt'))).strip()
        self.profile_api_user_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_USER_FIELD', toolkit.config.get('ckan.oauth2.profile_api_user_field', ''))).strip()
        self.profile_api_fullname_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD', toolkit.config.get('ckan.oauth2.profile_api_fullname_field', ''))).strip()
        self.profile_api_firstname_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_FIRSTNAME_FIELD', toolkit.config.get('ckan.oauth2.profile_api_firstname_field', ''))).strip()
        self.profile_api_lastname_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_LASTNAME_FIELD', toolkit.config.get('ckan.oauth2.profile_api_lastname_field', ''))).strip()
        self.profile_api_mail_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_MAIL_FIELD', toolkit.config.get('ckan.oauth2.profile_api_mail_field', ''))).strip()
        self.profile_api_groupmembership_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD', toolkit.config.get('ckan.oauth2.profile_api_groupmembership_field', ''))).strip()
        self.sysadmin_group_name = six.text_type(os.environ.get('CKAN_OAUTH2_SYSADMIN_GROUP_NAME', toolkit.config.get('ckan.oauth2.sysadmin_group_name', ''))).strip()

        self.redirect_uri = urljoin(urljoin(toolkit.config.get('ckan.site_url', 'http://localhost:5000'), toolkit.config.get('ckan.root_path')), REDIRECT_URL)

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def _compliance_fix(self, session):
        """Apply compliance hooks to the OAuth2 session."""
        def _fix_access_token(response):
            data = response.json()
            log.debug(f"data: {data}")
            if 'result' in data:
                # Just return the access token directly without additional encoding
                response._content = json.dumps(data['result']['access_token']).encode('utf-8')
            return response

        session.register_compliance_hook('access_token_response', _fix_access_token)
        # session.register_compliance_hook('refresh_token_response', _fix_access_token)
        return session

    def challenge(self, came_from_url):
        state = generate_state(came_from_url)
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope, state=state)
        oauth = self._compliance_fix(oauth)  # Apply compliance fixes
        auth_url, _ = oauth.authorization_url(self.authorization_endpoint)
        log.debug('Challenge: Redirecting challenge to page {0}'.format(auth_url))
        # CKAN 2.6 only supports bytes
        return toolkit.redirect_to(auth_url)#.encode('utf-8'))

    def get_token(self):
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope)
        oauth = self._compliance_fix(oauth)  # Apply compliance fixes

        # Just because of FIWARE Authentication
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if self.legacy_idm:
            # This is only required for Keyrock v6 and v5
            headers['Authorization'] = 'Basic %s' % base64.urlsafe_b64encode(
                (f'{self.client_id}:{self.client_secret}').encode()
            )

        try:
            authorization_response = toolkit.request.url.replace("http:", "https:", 1)
            token = oauth.fetch_token(self.token_endpoint,
                                      client_id=self.client_id,
                                      client_secret=self.client_secret,
                                      authorization_response=authorization_response,
                                      include_client_id=True)
        except requests.exceptions.SSLError as e:
            # TODO search a better way to detect invalid certificates
            if "verify failed" in six.text_type(e):
                raise InsecureTransportError()
            else:
                raise
        except Exception as e:
            log.debug(f'error: {e}')
            raise
        return token

    def identify(self, token):
        if self.jwt_enable:
            log.debug(f'jwt_enabled')
            log.debug(f'token: {token}')
            json_token_decoded = jwt.decode(token['access_token'], verify=False)
            username, email = self.extract_user_data_from_jwt(json_token_decoded)
            user = self.find_or_create_user(username, email)
            return user.name

        else:
            try:
                if self.legacy_idm:
                    profile_response = requests.get(self.profile_api_url + '?access_token=%s' % token['access_token'], verify=self.verify_https)
                    log.debug(f'profile response: {profile_response}')
                else:
                    log.debug(f'token: {token}')
                    headers = {
                        'X-Tapis-Token': token['access_token']
                    }
                    profile_response = requests.get(self.profile_api_url, headers=headers, verify=self.verify_https)
                    log.debug(f'profile response_: {profile_response}')

            except requests.exceptions.SSLError as e:
                log.debug('exception identify oauth2')
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise

            # Token can be invalid
            if not profile_response.ok:
                error = profile_response.json()
                if error.get('error', '') == 'invalid_token':
                    raise ValueError(error.get('error_description'))
                else:
                    profile_response.raise_for_status()
            else:
                log.debug(f'profile_response: {profile_response}')
                user_data = profile_response.json()['result']
                username, email = self.extract_user_data_from_oauth_response(user_data)
                user = self.find_or_create_user(username, email)

        log.debug(f'user: {user}')
        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        return user.name


    def extract_user_data_from_jwt(self, json_token_decoded):
        log.debug(f'json_token_decoded: {json_token_decoded}')
        email = json_token_decoded.get('tapis/email')
        user_name = json_token_decoded.get('tapis/username')

        if not user_name and not email:
            raise ValueError("Username or email is required but was not provided by OAuth provider")
        return email, user_name

    def extract_user_data_from_oauth_response(self, user_data):
        log.debug(f'user_data: {user_data}')
        email = user_data.get(self.profile_api_mail_field) if self.profile_api_mail_field else None
        user_name = user_data.get(self.profile_api_user_field) if self.profile_api_user_field else None

        if not user_name and not email:
            raise ValueError("Username or email is required but was not provided by OAuth provider")
        return email, user_name


    def find_or_create_user(self, username: Optional[str], email: Optional[str]) -> Optional[model.User]:
        # Try to find existing user by username first, then by email
        user = self.find_user(username, email)
        # Create new user if not found
        if not user:
            user = model.User(name=username, email=email)
        return user

    def find_user(self, username: Optional[str], email: Optional[str]) -> Optional[model.User]:
        if username:
            users = model.User.by_name(username)
            if isinstance(users, model.User):
                return users
            elif isinstance(users, list) and len(users) == 1:
                return users[0]

        if email:
            users = model.User.by_email(email)
            if isinstance(users, model.User):
                return users
            elif isinstance(users, list) and len(users) == 1:
                return users[0]
        return None

    def user_json(self, user_profile):
        # Extract user info from OAuth data
        email, user_name = self.extract_user_data_from_oauth_response(user_profile)
        user = self.find_or_create_user(user_name, email)

        # Update optional fields if provided
        if self.profile_api_fullname_field and self.profile_api_fullname_field in user_profile:
            user.fullname = user_profile[self.profile_api_fullname_field]
        elif self.profile_api_firstname_field and self.profile_api_lastname_field and self.profile_api_firstname_field in user_profile and self.profile_api_lastname_field in user_profile:
            user.fullname = f"{user_profile[self.profile_api_firstname_field]} {user_profile[self.profile_api_lastname_field]}"
        elif self.profile_api_firstname_field and self.profile_api_firstname_field in user_profile:
            user.fullname = user_profile[self.profile_api_firstname_field]
        elif self.profile_api_lastname_field and self.profile_api_lastname_field in user_profile:
            user.fullname = user_profile[self.profile_api_lastname_field]

        if self.profile_api_groupmembership_field and self.profile_api_groupmembership_field in user_profile:
            user.sysadmin = self.sysadmin_group_name in user_profile[self.profile_api_groupmembership_field]

        return user

    def _get_rememberer(self, environ):
        plugins = environ.get('repoze.who.plugins', {})
        return plugins.get(self.rememberer_name)

    def remember(self, user_name):
        '''
        Remember the authenticated identity.

        This method simply delegates to another IIdentifier plugin if configured.
        '''
        log.debug('Repoze OAuth remember')
        environ = toolkit.request.environ
        rememberer = self._get_rememberer(environ)
        identity = {'repoze.who.userid': user_name}
        headers = rememberer.remember(environ, identity)
        response = jsonify()
        for header, value in headers:
            response.headers[header] = value
        return response

    def redirect_from_callback(self, resp_remember):
        '''Redirect to the callback URL after a successful authentication.'''
        state = toolkit.request.params.get('state')
        came_from = get_came_from(state)

        response = jsonify()
        response.status_code = 302
        for header, value in resp_remember.headers:
            response.headers[header] = value
        response.headers['location'] = came_from
        response.autocorrect_location_header = False
        return response


    def get_stored_token(self, user_name):
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if user_token:
            return {
                'access_token': user_token.access_token,
                'refresh_token': user_token.refresh_token,
                'expires_in': user_token.expires_in,
                'token_type': user_token.token_type if user_token.token_type else 'new_token_type'
            }

    def update_token(self, user_name, token):
        try:
            user_token = db.UserToken.by_user_name(user_name=user_name)
        except AttributeError as e:
            user_token = None
        # Create the user if it does not exist
        if not user_token:
            user_token = db.UserToken()
            user_token.user_name = user_name
        # Save the new token
        user_token.access_token = token['access_token']
        user_token.token_type = 'new_token_type'
        user_token.refresh_token = token.get('refresh_token')
        if 'expires_in' in token:
            user_token.expires_in = token['expires_in']
        else:
            access_token = jwt.decode(user_token.access_token, verify=False)
            user_token.expires_in = access_token['exp'] - access_token['iat']

        model.Session.add(user_token)
        model.Session.commit()

    def refresh_token(self, user_name):
        token = self.get_stored_token(user_name)
        if token:
            client = OAuth2Session(self.client_id, token=token, scope=self.scope)
            client = self._compliance_fix(client)  # Apply compliance fixes
            try:
                token = client.refresh_token(self.token_endpoint, client_secret=self.client_secret, client_id=self.client_id, verify=self.verify_https)
            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise
            self.update_token(user_name, token)
            log.info('Token for user %s has been updated properly' % user_name)
            return token
        else:
            log.warn('User %s has no refresh token' % user_name)
