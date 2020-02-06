#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json
try:
    from urllib.parse import urlparse
except Exception:
    # PY2 compat
    from urlparse import urlparse
import requests


class IntrospectionNotAvailableError(Exception):
    pass


def get_cookie(auth_server,
               username=None, password=None,
               github_access_token=None,
               api_key=None,
               use_ssl=True,
               verify=True):
    # TODO: remove this parameter once
    #       I8df68b7f74344371e4b45b4a6d1cc3362b70b61e is merged
    if use_ssl is False:
        use_ssl = True
    if urlparse(auth_server).scheme == '':
        auth_server = "https://%s" % auth_server
    cauth_info = get_cauth_info(auth_server, verify)
    url = "%s/auth/login" % auth_server
    auth_params = {'back': '/',
                   'args': {}, }
    methods = cauth_info['service']['auth_methods']
    if (username and password and ('Password' in methods)):
        auth_params['args'] = {'username': username,
                               'password': password}
        auth_params['method'] = 'Password'
    elif (github_access_token and
          ('GithubPersonalAccessToken' in methods)):
        auth_params['args'] = {'token': github_access_token}
        auth_params['method'] = 'GithubPersonalAccessToken'
    elif (api_key and ('APIKey' in methods)):
        auth_params['args'] = {'api_key': api_key}
        auth_params['method'] = 'APIKey'
    else:
        m = "Missing credentials (accepted auth methods: %s)"
        methods = ','.join(methods)
        raise ValueError(m % methods)
    header = {'Content-Type': 'application/json'}
    resp = requests.post(url, json.dumps(auth_params, sort_keys=True),
                         allow_redirects=False,
                         verify=verify,
                         headers=header)
    return resp.cookies.get('auth_pubtkt', '')


def _get_service_info(url, verify=True):
    resp = requests.get(url, allow_redirects=False,
                        verify=verify)
    return resp.json()


def get_cauth_info(auth_server, verify=True):
    url = "%s/auth/about/" % auth_server
    return _get_service_info(url, verify)


def get_managesf_info(auth_server, verify=True):
    url = "%s/about/" % auth_server
    return _get_service_info(url, verify)
