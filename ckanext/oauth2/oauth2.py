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
        self.jwt_algorithm = six.text_type(os.environ.get('CKAN_OAUTH2_JWT_ALGORITHM', toolkit.config.get('ckan.oauth2.jwt.algorithm', 'HS256'))).strip()
        self.jwt_secret = six.text_type(os.environ.get('CKAN_OAUTH2_JWT_SECRET', toolkit.config.get('ckan.oauth2.jwt.secret', ''))).strip()
        self.jwt_public_key = six.text_type(os.environ.get('CKAN_OAUTH2_JWT_PUBLIC_KEY', toolkit.config.get('ckan.oauth2.jwt.public_key', ''))).strip()

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

    def query_profile_api_legacy(self, token):
        try:
            profile_response = requests.get(self.profile_api_url + '?access_token=%s' % token['access_token'], verify=self.verify_https)
            if not profile_response.ok:
                raise ValueError(profile_response.json().get('error_description'))
            return profile_response
        except Exception as e:
            log.error(f'error: {e}')
            raise

    def query_profile_api_default(self, token):
        try:
            headers = {
                'X-Tapis-Token': token['access_token']
            }
            profile_response = requests.get(self.profile_api_url, headers=headers, verify=self.verify_https)
            if not profile_response.ok:
                raise ValueError(profile_response.json().get('error_description'))
            return profile_response
        except Exception as e:
            log.error(f'error: {e}')
            raise

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
        raise ValueError("User not found")

    def create_user_object(self, user_profile) -> model.User:
        email = user_profile.get(self.profile_api_mail_field) if self.profile_api_mail_field else None
        username = user_profile.get(self.profile_api_user_field) if self.profile_api_user_field else None
        if not username and not email:
            raise ValueError("Username or email is required but was not provided by OAuth provider")
        user = model.User(name=username, email=email)
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

    def identify(self, token):
        if self.jwt_enable:
            access_token = token['access_token']
            # Check if we have the appropriate key for verification
            has_key = (self.jwt_algorithm.startswith('HS') and self.jwt_secret) or \
                     (self.jwt_algorithm.startswith(('RS', 'ES')) and self.jwt_public_key)
            if not has_key:
                raise ValueError("JWT secret or public key not configured for algorithm %s" % self.jwt_algorithm)
            token_decoded = self._decode_jwt(access_token, verify=True)

            email = token_decoded.get('tapis/email')
            username = token_decoded.get('tapis/username')
            try:
                user = self.find_user(username, email)
            except ValueError:
                profile_response = self.query_profile_api_legacy(token) if self.legacy_idm else self.query_profile_api_default(token)
                user = self.create_user_object(profile_response.json()['result'])
        else:
            profile_response = self.query_profile_api_legacy(token) if self.legacy_idm else self.query_profile_api_default(token)
            user_profile = profile_response.json()['result']
            try:
                user = self.find_user(user_profile.get(self.profile_api_user_field), user_profile.get(self.profile_api_mail_field))
            except ValueError:
                user = self.create_user_object(user_profile)
        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()
        return user.name


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
        else:
            return None

    def _decode_jwt(self, token, verify=True):
        """
        Decode JWT token using configured algorithm and secret/public key.
        """
        try:
            if verify:
                # Determine the key to use based on algorithm
                if self.jwt_algorithm.startswith('HS'):
                    # Symmetric algorithms (HS256, HS384, HS512) use shared secret
                    if self.jwt_secret:
                        return jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
                    else:
                        log.error('JWT secret not configured for symmetric algorithm %s, rejecting token', self.jwt_algorithm)
                        raise ValueError('JWT secret not configured for symmetric algorithm')
                elif self.jwt_algorithm.startswith('RS') or self.jwt_algorithm.startswith('ES'):
                    # Asymmetric algorithms (RS256, ES256, etc.) use public key
                    if self.jwt_public_key:
                        return jwt.decode(token, self.jwt_public_key, algorithms=[self.jwt_algorithm])
                    else:
                        log.error('JWT public key not configured for asymmetric algorithm %s, rejecting token', self.jwt_algorithm)
                        raise ValueError('JWT public key not configured for asymmetric algorithm')
                else:
                    log.error('Unknown JWT algorithm %s, rejecting token', self.jwt_algorithm)
                    raise ValueError('Unknown JWT algorithm')
            else:
                return jwt.decode(token, verify=True)
        except (jwt.DecodeError, jwt.InvalidTokenError) as e:
            log.error('JWT decode error: %s', str(e))
            raise

    def update_token(self, user_name, token):
        try:
            user_token = db.UserToken.by_user_name(user_name=user_name)
        except AttributeError:
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
            access_token = self._decode_jwt(user_token.access_token, verify=True)
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
