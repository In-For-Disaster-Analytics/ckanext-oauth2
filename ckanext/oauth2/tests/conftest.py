import pytest
import ckan.plugins as plugins
import ckan.tests.factories as factories
import ckan.tests.helpers as helpers
import ckanext.oauth2.plugin as plugin
import os
import ckan.model as model
from ckan.config.middleware import make_app
from paste.deploy import loadapp
from webtest import TestApp

@pytest.fixture(scope="session")
def app():
    """Create a test app with the oauth2 plugin enabled"""
    config = {
        'ckan.site_id': 'test',
        'ckan.site_url': 'http://localhost',
        'ckan.plugins': 'oauth2',
        'ckan.oauth2.authorization_endpoint': 'https://test/oauth2/authorize/',
        'ckan.oauth2.token_endpoint': 'https://test/oauth2/token/',
        'ckan.oauth2.client_id': 'client-id',
        'ckan.oauth2.client_secret': 'client-secret',
        'ckan.oauth2.profile_api_url': 'https://test/oauth2/user',
        'ckan.oauth2.profile_api_user_field': 'nickName',
        'ckan.oauth2.profile_api_mail_field': 'mail',
        'ckan.oauth2.authorization_header': 'authorization',
        'ckan.oauth2.legacy_idm': 'false',
    }

    app = make_app(loadapp('config:test.ini', relative_to='.'), **config)
    return TestApp(app)

@pytest.fixture
def oauth2_plugin():
    """Enable the oauth2 plugin for tests"""
    with plugins.use_plugin('oauth2') as oauth2_plugin:
        yield oauth2_plugin

@pytest.fixture
def mock_toolkit(monkeypatch):
    """Mock CKAN toolkit functions"""
    mock = helpers.MagicMock()
    mock.config = {
        'ckan.oauth2.authorization_header': 'authorization',
        'ckan.oauth2.authorization_endpoint': 'https://test/oauth2/authorize/',
        'ckan.oauth2.token_endpoint': 'https://test/oauth2/token/',
        'ckan.oauth2.client_id': 'client-id',
        'ckan.oauth2.client_secret': 'client-secret',
        'ckan.oauth2.profile_api_url': 'https://test/oauth2/user',
        'ckan.oauth2.profile_api_user_field': 'nickName',
        'ckan.oauth2.profile_api_mail_field': 'mail',
        'ckan.oauth2.legacy_idm': 'false',
    }
    monkeypatch.setattr(plugin, 'toolkit', mock)
    return mock

@pytest.fixture(autouse=True)
def setup_test_env():
    """Set up test environment variables"""
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    yield
    os.environ.pop('OAUTHLIB_INSECURE_TRANSPORT', None)

@pytest.fixture(autouse=True)
def reset_db():
    """Reset the database before each test"""
    model.repo.rebuild_db()
    yield
    model.repo.rebuild_db()