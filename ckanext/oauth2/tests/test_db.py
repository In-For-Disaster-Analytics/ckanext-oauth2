# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid

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
from ckanext.oauth2 import db


class TestDB:

    def test_user_token_class_exists(self):
        """Test that UserToken class is defined"""
        assert db.UserToken is not None
        assert hasattr(db.UserToken, 'by_user_name')

    def test_user_token_table_exists(self):
        """Test that user_token_table is defined"""
        assert db.user_token_table is not None
        assert db.user_token_table.name == 'user_token'

    def test_user_token_table_columns(self):
        """Test that user_token_table has the correct columns"""
        columns = {c.name for c in db.user_token_table.columns}
        expected_columns = {'user_name', 'access_token', 'token_type', 'refresh_token', 'expires_in'}
        assert columns == expected_columns

    def test_init_db(self):
        """Test that init_db runs without errors"""
        # This should not raise any exceptions
        db.init_db()
