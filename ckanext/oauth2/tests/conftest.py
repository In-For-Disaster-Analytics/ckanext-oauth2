import pytest
import ckan.plugins as plugins
import ckan.tests.factories as factories
import ckan.tests.helpers as helpers
import ckanext.oauth2.plugin as plugin

@pytest.fixture
def app():
    app = helpers._get_test_app()
    with app.flask_app.test_request_context():
        yield app

@pytest.fixture
def oauth2_plugin():
    with plugins.use_plugin('oauth2') as oauth2_plugin:
        yield oauth2_plugin

@pytest.fixture
def mock_toolkit(monkeypatch):
    """Mock CKAN toolkit functions"""
    mock = helpers.MagicMock()
    mock.config = {'ckan.oauth2.authorization_header': 'authorization'}
    monkeypatch.setattr(plugin, 'toolkit', mock)
    return mock