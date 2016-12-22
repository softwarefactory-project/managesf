#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat <licensing@enovance.com>
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

import paramiko

from managesf.services import base
from managesf.services.nodepool import node, image


class _Nodepool(base.BaseAgentProviderServicePlugin):
    """Plugin managing the Nodepool agent provider service."""

    _config_section = "nodepool"
    service_name = "nodepool"

    def __init__(self, conf):
        super(_Nodepool, self).__init__(conf)

    def get_client(self, cookie=None):
        raise NotImplementedError


class SoftwareFactoryNodepool(_Nodepool):
    """Plugin managing the Nodepool service on Software Factory.
    Nodepool does not yet expose a REST API so commands are issued through
    calls to the CLI over SSH."""

    # config fields:
    # * host: the host to ssh into
    # * user: the user to use ssh with
    # * key: path to the private key to use for the connection

    def __init__(self, conf):
        super(SoftwareFactoryNodepool, self).__init__(conf)
        self.node = node.SFNodepoolNodeManager(self)
        self.image = image.SFNodepoolImageManager(self)

    def get_client(self, *args, **kwargs):
        k = paramiko.RSAKey.from_private_key_file(self.conf['key'])
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=self.conf['host'],
                  username=self.conf['user'],
                  pkey=k)
        return c
