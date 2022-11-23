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

import requests


class IntrospectionNotAvailableError(Exception):
    pass


def _get_service_info(url, verify=True):
    resp = requests.get(url, allow_redirects=False,
                        verify=verify)
    return resp.json()


def get_managesf_info(auth_server, verify=True):
    url = "%s/about/" % auth_server
    return _get_service_info(url, verify)
