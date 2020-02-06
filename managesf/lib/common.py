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


import requests


def _get(url, verify=True):
    resp = requests.get(url, allow_redirects=False,
                        verify=verify)
    return resp.json()


def get_cauth_info(auth_server, verify=True):
    url = "%s/auth/about/" % auth_server
    return _get(url, verify)


def get_managesf_info(gateway_url, verify=True):
    url = "%s/manage/about/" % gateway_url
    return _get(url, verify).get('service', {}).get('services', [])
