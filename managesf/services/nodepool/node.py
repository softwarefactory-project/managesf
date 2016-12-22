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


import logging

from managesf.services import base
from managesf.services.nodepool.common import get_values, get_age
from managesf.services.nodepool.common import validate_input, validate_ssh_key


logger = logging.getLogger(__name__)


LIST_CMD = 'nodepool list | sed -e 1,3d -e "$ d"'
LIST_FIELDS = ['node_id', 'provider_name', 'AZ', 'label', 'target', 'manager',
               'hostname', 'node_name', 'server_id', 'ip', 'state', 'age']
HOLD_CMD = 'nodepool hold %i'
DELETE_CMD = 'nodepool delete %i'
# TODO the path to jenkins' key should be a parameter or a config element
KEY_CMD = ('echo "%(key)s" | ssh -o StrictHostKeyChecking=no '
           '-i /var/lib/jenkins/.ssh/id_rsa %(user)s@%(ip)s'
           ' "cat >> ~/.ssh/authorized_keys"')


class SFNodepoolNodeManager(base.NodeManager):
    """Node management through Nodepool's CLI, called via SSH"""

    def __init__(self, plugin):
        super(SFNodepoolNodeManager, self).__init__(plugin)

    def get(self, node_id=None, **kwargs):
        """lists one or several nodes depending on filtering with node's
        id or kwargs"""
        if node_id and not isinstance(node_id, int):
            raise Exception("invalid node id %r" % node_id)
        nodes_info = []
        client = self.plugin.get_client()
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          LIST_CMD))
        stdin, stdout, stderr = client.exec_command(LIST_CMD)
        return_code = int(stdout.channel.recv_exit_status())
        client.close()
        if return_code > 0:
            e = stderr.read()
            m = "[%s] node get failed with exit code %i: %s"
            m = m % (self.plugin.service_name, return_code, e)
            logger.error(m)
            raise Exception(m)
        for line in stdout.readlines():
            values = get_values(line)
            node = dict(zip(LIST_FIELDS, values))
            node['age'] = get_age(node['age'])
            if node_id:
                if node_id == int(node['node_id']):
                    nodes_info = [node, ]
                    break
            else:
                nodes_info.append(node)
        return nodes_info

    def hold(self, node_id):
        """prevents node node_id from being deleted after a completed job"""
        if not isinstance(node_id, int):
            raise Exception("invalid node id %r" % node_id)
        client = self.plugin.get_client()
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          (HOLD_CMD % node_id)))
        stdin, stdout, stderr = client.exec_command(HOLD_CMD % node_id)
        return_code = int(stdout.channel.recv_exit_status())
        client.close()
        if return_code > 0:
            e = stderr.read()
            m = "[%s] node hold failed with exit code %i: %s"
            m = m % (self.plugin.service_name, return_code, e)
            logger.error(m)
            raise Exception(m)

    def delete(self, node_id):
        """schedules node node_id for deletion"""
        if not isinstance(node_id, int):
            raise Exception("invalid node id %r" % node_id)
        client = self.plugin.get_client()
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          (DELETE_CMD % node_id)))
        stdin, stdout, stderr = client.exec_command(DELETE_CMD % node_id)
        return_code = int(stdout.channel.recv_exit_status())
        client.close()
        if return_code > 0:
            e = stderr.read()
            m = "[%s] node delete failed with exit code %i: %s"
            m = m % (self.plugin.service_name, return_code, e)
            logger.error(m)
            raise Exception(m)

    def add_authorized_key(self, node_id, public_key, user=None):
        """adds public_key as an authorized key on user's account on node_id"""
        if not user:
            user = 'jenkins'
        if not isinstance(node_id, int):
            raise Exception("invalid node id %r" % node_id)
        if not validate_input(user):
            raise Exception("invalid user %s" % user)
        try:
            validate_ssh_key(public_key)
        except ValueError:
            raise Exception("invalid public key %s(...)" % public_key[:15])
        node = self.get(node_id=node_id)
        if not node:
            raise Exception('Node %i not found' % node_id)
        ip = node[0]['ip']
        cmd = KEY_CMD % {'key': public_key, 'user': user, 'ip': ip}
        client = self.plugin.get_client()
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          cmd))
        stdin, stdout, stderr = client.exec_command(cmd)
        return_code = int(stdout.channel.recv_exit_status())
        client.close()
        if return_code > 0:
            e = stderr.read()
            m = "[%s] public key insertion failed with exit code %i: %s"
            m = m % (self.plugin.service_name, return_code, e)
            logger.error(m)
            raise Exception(m)
