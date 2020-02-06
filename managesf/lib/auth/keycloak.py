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


import requests # noqa
from urllib.parse import urlparse

from managesf.lib.auth.base import BaseAuthenticator


class KeycloakAuthenticator(BaseAuthenticator):

    def get_request_args(self, remote_gateway,
                         username=None, password=None,
                         verify=True,
                         **kwargs):
        # fetch the well-known conf and endpoint
        # TODO we should have a manageSF endpoint that gives us the endpoint
        # rather than guessing it this way.
        if urlparse(remote_gateway).scheme == '':
            remote_gateway = "https://%s" % remote_gateway
        # TODO realm should be a parameter?
        conf_url = "%s/auth/realms/sf/.well-known/openid-configuration"
        kc_conf = requests.get(conf_url % remote_gateway).json()
        token_endpoint = kc_conf.get("token_endpoint")
        if token_endpoint is None:
            raise Exception("No token endpoint found")
        # get the token
        data = {
            'username': username,
            'password': password,
            'grant_type': 'password',
            'client_id': 'managesf',
        }
        token_request = requests.post(
            token_endpoint,
            data,
            verify=verify)
        try:
            token = token_request.json()['access_token']
        except Exception:
            raise Exception(
                'Failure when fetching token: %s' % token_request.status_code)
        return {'headers': {'Authorization': 'bearer %s' % token}}
