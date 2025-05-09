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
import ckanext.oauth2.db as db
from unittest.mock import MagicMock

@pytest.fixture
def mock_sa(monkeypatch):
    """Mock SQLAlchemy"""
    mock = MagicMock()
    monkeypatch.setattr(db, 'sa', mock)
    return mock

@pytest.fixture(autouse=True)
def reset_db():
    """Reset database state before and after each test"""
    db.UserToken = None
    yield
    db.UserToken = None

def test_initdb_not_initialized(mock_sa):
    """Test database initialization when not initialized"""
    # Call the function
    model = MagicMock()
    db.init_db(model)

    # Assert that table method has been called
    mock_sa.Table.assert_called_once()
    model.meta.mapper.assert_called_once()

def test_initdb_initialized(mock_sa):
    """Test database initialization when already initialized"""
    db.UserToken = MagicMock()

    # Call the function
    model = MagicMock()
    db.init_db(model)

    # Assert that table method has been called
    assert mock_sa.Table.call_count == 0
    assert model.meta.mapper.call_count == 0
