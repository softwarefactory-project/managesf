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


import atexit
import logging

from managesf import model
from managesf.services import base
from managesf.services.nodepool.common import get_values, get_age
from managesf.services.nodepool.common import validate_input


logger = logging.getLogger(__name__)


crud = model.ImageUpdatesCRUD()


LIST_CMD = 'nodepool image-list | sed -e 1,3d -e "$ d"'
LIST_FIELDS = ['id', 'provider_name', 'image_name', 'hostname', 'version',
               'image_id', 'server_id', 'state', 'age']
UPDATE_CMD = ('nodepool image-update %(provider)s %(image)s')

DIB_LIST_CMD = 'nodepool dib-image-list | sed -e 1,3d -e "$ d"'
DIB_LIST_FIELDS = ['id', 'image', 'filename', 'version', 'state', 'age']

# TODO(mhu) is it safe to merge these two into one call?
DIB_BUILD_CMD = 'nodepool image-build %(image)s'
IMAGE_UPLOAD_CMD = ("timeout 1800 sed '/%(pattern)s/q "
                    "<(tail -f -n0 /var/log/nodepool/%(logfile)s) && "
                    "nodepool image-upload %(provider)s %(image)s")

# BUILDER_LOGS_CMD = 'journalctl -u nodepool-builder --no-pager'

UPDATES_CACHE = {}
REFRESH_LOCKED = False


def _refresh_cache():
    global REFRESH_LOCKED
    if REFRESH_LOCKED:
        logger.debug("image update cache is locked, refresh it later")
        return
    to_remove = []
    REFRESH_LOCKED = True
    logger.debug("locking image update cache for refresh")
    for u in UPDATES_CACHE:
        if UPDATES_CACHE[u]['stdout'].channel.exit_status_ready():
            stdout = UPDATES_CACHE[u]['stdout']
            stderr = UPDATES_CACHE[u]['stderr']
            client = UPDATES_CACHE[u]['client']
            exit_code = int(stdout.channel.recv_exit_status())
            if exit_code > 0:
                status = "FAILURE"
            else:
                status = "SUCCESS"
            crud.update(id=u, status=status, exit_code=str(exit_code),
                        output=stdout.read(), stderr=stderr.read())
            client.close()
            to_remove.append(u)
    for u in to_remove:
        del UPDATES_CACHE[u]
    REFRESH_LOCKED = False
    logger.debug("image update cache unlocked")


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

    def start_update(self, provider_name, image_name):
        """updates (rebuild) the image image_name on provider provider_name"""
        _refresh_cache()
        if (not validate_input(provider_name) or
           not validate_input(image_name)):
            msg = "invalid provider %r and/or image %r" % (provider_name,
                                                           image_name)
            raise Exception(msg)
        client = self.plugin.get_client()
        args = {'provider': provider_name,
                'image': image_name}
        update_id = int(crud.create(**args))
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          UPDATE_CMD % args))
        cmd = UPDATE_CMD % args
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        UPDATES_CACHE[update_id] = {'stdout': stdout,
                                    'stderr': stderr,
                                    'client': client}
        UPDATES_CACHE[update_id].update(args)
        return update_id

    def get_update_info(self, id):
        """fetches relevant info on an image update possibly still
        in progress"""
        _refresh_cache()
        x = crud.get(id)
        if x:
            return {'id': id,
                    'status': x['status'],
                    'provider': x['provider'],
                    'image': x['image'],
                    'exit_code': x['exit_code'],
                    'output': x['output'],
                    'error': x['stderr']}
        elif int(id) in UPDATES_CACHE:
            # TODO(mhu) Find a way to return the output in progress. Could we
            # copy the file-like stdout object?
            return {'id': id,
                    'status': 'IN_PROGRESS',
                    'provider': UPDATES_CACHE['provider'],
                    'image': UPDATES_CACHE['image'],
                    'exit_code': None,
                    'output': None,
                    'error': None}
        else:
            return {}


class SFNodepoolDIBImageManager(SFNodepoolImageManager):
    """Disk Image Builder related operations from Nodepool's CLI, via SSH"""

    def get(self, image_name=None, **kwargs):
        """lists one or several images depending on filtering options"""
        images_info = []
        client = self.plugin.get_client()
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          DIB_LIST_CMD))
        stdin, stdout, stderr = client.exec_command(DIB_LIST_CMD)
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
            image = dict(zip(DIB_LIST_FIELDS, values))
            image['age'] = get_age(image['age'])
            if image_name:
                if image_name == image['image']:
                    images_info.append(image)
            else:
                images_info.append(image)
        return images_info

    def start_update(self, provider_name, image_name):
        """rebuild the image image_name, then uploads it to"""
        """provider provider_name"""
        _refresh_cache()
        if (not validate_input(provider_name) or
           not validate_input(image_name)):
            msg = "invalid provider %r and/or image %r" % (provider_name,
                                                           image_name)
            raise Exception(msg)
        client = self.plugin.get_client()
        args = {'provider': provider_name,
                'image': image_name}
        update_id = int(crud.create(**args))
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          DIB_BUILD_CMD % args))
        cmd = DIB_BUILD_CMD % args
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        return_code = int(stdout.channel.recv_exit_status())
        if return_code > 0:
            UPDATES_CACHE[update_id] = {'stdout': stdout,
                                        'stderr': stderr,
                                        'client': client}
            UPDATES_CACHE[update_id].update(args)
            return update_id
        # TODO
        args['pattern'] = ''
        args['logfile'] = ''
        logger.debug("[%s] calling %s" % (self.plugin.service_name,
                                          IMAGE_UPLOAD_CMD % args))
        cmd = IMAGE_UPLOAD_CMD % args
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        UPDATES_CACHE[update_id] = {'stdout': stdout,
                                    'stderr': stderr,
                                    'client': client}
        del args['pattern']
        del args['logfile']
        UPDATES_CACHE[update_id].update(args)
        return update_id


# For the DBZ fans
def final_flush():
    from sqlalchemy.exc import OperationalError
    try:
        _refresh_cache()
        for u in UPDATES_CACHE:
            stdout = UPDATES_CACHE[u]['stdout']
            stderr = UPDATES_CACHE[u]['stderr']
            client = UPDATES_CACHE[u]['client']
            status = "INTERRUPTED"
            crud.update(id=u, status=status, output=stdout.read(),
                        stderr=stderr.read())
            client.close()
    except OperationalError as e:
        msg = "[img-update] Error handling final cache flush on db: %s"
        logger.error(msg % e)
    except Exception as e:
        msg = "[img-update] Unknown error handling final cache flush: %s"
        logger.error(msg % e)


atexit.register(final_flush)
