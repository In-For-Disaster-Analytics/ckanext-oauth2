# -*- coding: utf-8 -*-

# Copyright (c) 2014 - 2017 CoNWeT Lab., Universidad Politécnica de Madrid
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

from __future__ import print_function

import os
import pytest
import time
from subprocess import Popen
from urllib.parse import urljoin

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

IDM_URL = "http://localhost:3000"
FILAB2_MAIL = "admin@test.com"
FILAB_PASSWORD = "1234"
PASS_INTEGRATION_TESTS = os.environ.get("INTEGRATION_TEST", "").strip().lower() in ('1', 'true', 'on')
AUTH_TOKEN_ENDPOINT = "v1/auth/tokens"
APPLICATION_ENDPOINT = "v1/applications"

pytestmark = pytest.mark.skipif(not PASS_INTEGRATION_TESTS,
                               reason="set INTEGRATION_TEST environment variable (e.g. INTEGRATION_TEST=true) for running the integration tests")

@pytest.fixture(scope="class")
def selenium_driver():
    """Set up and tear down the Selenium WebDriver"""
    if not PASS_INTEGRATION_TESTS:
        return

    # Get an admin token
    body = {
        "name": "admin@test.com",
        "password": "1234"
    }
    url = urljoin(IDM_URL, AUTH_TOKEN_ENDPOINT)
    response = requests.post(url, json=body)
    print(response.text)

    token = response.headers["X-Subject-Token"]

    # Create the OAuth2 application
    headers = {
        "X-Auth-Token": token
    }

    body = {
        "application": {
            "name": "Travis Selenium Tests",
            "description": "Travis Selenium Tests",
            "redirect_uri": "http://localhost:5000/oauth2/callback",
            "url": "http://localhost:5000",
            "grant_type": [
                "authorization_code"
            ]
        }
    }

    url = urljoin(IDM_URL, APPLICATION_ENDPOINT)
    response = requests.post(url, json=body, headers=headers)
    app = response.json()

    # Run CKAN
    env = os.environ.copy()
    env['DEBUG'] = 'True'
    env['OAUTHLIB_INSECURE_TRANSPORT'] = 'False'
    env['CKAN_OAUTH2_CLIENT_ID'] = app['application']['id']
    env['CKAN_OAUTH2_CLIENT_SECRET'] = app['application']['secret']
    process = Popen(['paster', 'serve', 'test-fiware.ini'], env=env)

    # Init Selenium
    driver = webdriver.Firefox()
    driver.base_url = 'http://localhost:5000/'
    driver.set_window_size(1024, 768)

    yield driver

    # Cleanup
    process.terminate()
    driver.quit()

@pytest.fixture(autouse=True)
def setup_teardown(selenium_driver):
    """Set up and tear down for each test"""
    if not PASS_INTEGRATION_TESTS:
        return

    selenium_driver.get(selenium_driver.base_url)
    selenium_driver.delete_all_cookies()
    selenium_driver.get(IDM_URL)
    selenium_driver.delete_all_cookies()
    yield

def introduce_log_in_parameters(driver, username=FILAB2_MAIL, password=FILAB_PASSWORD):
    """Helper function to fill in login form"""
    id_username = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "id_email")))
    id_username.clear()
    id_username.send_keys(username)
    driver.find_element_by_id("id_password").clear()
    driver.find_element_by_id("id_password").send_keys(password)
    driver.find_element_by_xpath("//button[@type='submit']").click()
    WebDriverWait(driver, 30).until(EC.staleness_of(id_username))

def log_in(driver, referer, username=FILAB2_MAIL, password=FILAB_PASSWORD, authorize=True):
    """Helper function to perform login"""
    driver.get(referer)
    WebDriverWait(driver, 30).until(lambda d: d.current_url == referer)

    WebDriverWait(driver, 30).until(EC.element_to_be_clickable((By.LINK_TEXT, "Log in"))).click()
    introduce_in_parameters(driver, username, password)

    if driver.current_url.startswith(IDM_URL) and authorize:
        WebDriverWait(driver, 30).until(EC.element_to_be_clickable((By.XPATH, "//button[@type='submit']"))).click()

def test_basic_login(selenium_driver):
    """Test basic login functionality"""
    driver = selenium_driver
    log_in(driver, driver.base_url)
    WebDriverWait(driver, 20).until(lambda d: (driver.base_url + 'dashboard') == d.current_url)
    assert driver.find_element_by_link_text("admin").text == "admin"
    driver.find_element_by_link_text("About").click()
    WebDriverWait(driver, 20).until(lambda d: (driver.base_url + 'about') == d.current_url)
    assert driver.find_element_by_css_selector("span.username").text == "admin"
    driver.find_element_by_css_selector("a[title=\"Edit settings\"]").click()
    time.sleep(3)   # Wait the OAuth2 Server to return the page
    assert driver.current_url.startswith(IDM_URL + "/idm/settings"), f"{driver.current_url} does not starts with {IDM_URL}/idm/settings"

def test_basic_login_different_referer(selenium_driver):
    """Test login from a different referer page"""
    driver = selenium_driver
    log_in(driver, driver.base_url + "about")
    WebDriverWait(driver, 20).until(lambda d: (driver.base_url + 'about') == d.current_url)
    assert driver.find_element_by_css_selector("span.username").text == "admin"
    driver.find_element_by_link_text("Datasets").click()
    WebDriverWait(driver, 20).until(lambda d: (driver.base_url + 'dataset') == d.current_url)
    assert driver.find_element_by_css_selector("span.username").text == "admin"

def test_user_access_unauthorized_page(selenium_driver):
    """Test access to unauthorized page"""
    driver = selenium_driver
    log_in(driver, driver.base_url)
    driver.get(driver.base_url + "ckan-admin")

    # Check that an error message is shown
    assert "Need to be system administrator to administer" in driver.find_element_by_tag_name('body').text

def test_register_btn(selenium_driver):
    """Test register button functionality"""
    driver = selenium_driver
    driver.get(driver.base_url)
    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.LINK_TEXT, "Register"))).click()
    WebDriverWait(driver, 10).until(lambda d: d.current_url == (IDM_URL + "/sign_up"))

@pytest.mark.parametrize('action,expected_url', [
    ("user/register", IDM_URL + "/sign_up"),
    ("user/reset", IDM_URL + "/password/request")
])
def test_register(selenium_driver, action, expected_url):
    """Test register and reset password functionality"""
    driver = selenium_driver
    driver.get(driver.base_url + action)
    WebDriverWait(driver, 10).until(lambda d: print(d.current_url) or d.current_url == expected_url)
