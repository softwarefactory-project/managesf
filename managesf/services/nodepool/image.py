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
# from managesf.services.nodepool.common import validate_input


logger = logging.getLogger(__name__)


LIST_CMD = 'nodepool image-list | sed -e 1,3d -e "$ d"'
LIST_FIELDS = ['id', 'provider_name', 'image_name', 'hostname', 'version',
               'image_id', 'server_id', 'state', 'age']
UPDATE_CMD = ('nodepool -l /etc/nodepool/logging.conf '
              'image-update %(provider)s %(image)s')


class SFNodepoolImageManager(base.ImageManager):
    """Image related operations from Nodepool's CLI, via SSH"""
    def __init__(self, plugin):
        super(SFNodepoolImageManager, self).__init__(plugin)

    def get(self, provider_name=None, image_name=None, **kwargs):
        """lists one or several images depending on filtering options"""
        images_info = []
        client = self.plugin.get_client()
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          LIST_CMD))
        stdin, stdout, stderr = client.exec_command(LIST_CMD)
        return_code = int(stdout.channel.recv_exit_status())
        client.close()
        if return_code > 0:
            e = stderr.read()
            m = "[%s] image get failed with exit code %i: %s"
            m = m % (self.plugin.service_name, return_code, e)
            logger.error(m)
            raise Exception(m)
        for line in stdout.readlines():
            values = get_values(line)
            image = dict(zip(LIST_FIELDS, values))
            image['age'] = get_age(image['age'])
            if provider_name and image_name:
                if (provider_name == image['provider_name'] and
                   image_name == image['image_name']):
                    images_info.append(image)
            elif provider_name:
                if provider_name == image['provider_name']:
                    images_info.append(image)
            elif image_name:
                if image_name == image['image_name']:
                    images_info.append(image)
            else:
                images_info.append(image)
        return images_info

# TODO look more into the app_iter mechanism before going this way
#    def update(self, provider_name, image_name):
#        """updates (rebuild) the image image_name on provider provider_name"""
#        if (not validate_input(provider_name) or
#           not validate_input(image_name)):
#            msg = "invalid provider %r and/or image %r" % (provider_name,
#                                                           image_name)
#            raise Exception(msg)
#        client = self.plugin.get_client()
#        args = {'provider': provider_name,
#                'image': image_name}
#        logger.debug("[%s] calling %s" % (self.plugin.service_name,
#                                          UPDATE_CMD % args))
#        cmd = UPDATE_CMD % args
#        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
#        client.close()
#        return stdout
