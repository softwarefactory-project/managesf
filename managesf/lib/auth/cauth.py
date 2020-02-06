#
# Copyright (C) 2020 Red Hat
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
from urllib.parse import urlparse
import requests

from managesf.lib.common import get_cauth_info
from managesf.lib.auth.base import BaseAuthenticator


class CAuthAuthenticator(BaseAuthenticator):

    def get_request_args(self, remote_gateway,
                         username=None, password=None,
                         github_access_token=None,
                         api_key=None,
                         use_ssl=True,
                         verify=True, **kwargs):
        req_args = {}
        if use_ssl is False:
            use_ssl = True
        if urlparse(remote_gateway).scheme == '':
            remote_gateway = "https://%s" % remote_gateway
        cauth_info = get_cauth_info(remote_gateway, verify)
        url = "%s/auth/login" % remote_gateway
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
        cookie = resp.cookies.get('auth_pubtkt', '')
        req_args['cookies'] = {'auth_pubtkt': cookie}
        req_args['headers'] = {'X-Remote-User': username}
        return req_args
