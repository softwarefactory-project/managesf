#
# Copyright (c) 2015 Red Hat, Inc.
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

from pecan import conf

from urlparse import urlparse

logger = logging.getLogger(__name__)


class InvalidInfosInput(Exception):
    pass


class PageNotFound(Exception):
    pass


def verify_input(infos):
    if 'url' in infos.keys():
        ret = urlparse(infos['url'])
        for k in ('scheme', 'netloc'):
            if not getattr(ret, k):
                raise InvalidInfosInput()


def read_maps():
    maps_path = conf.pages['maps']
    maps = {}
    lines = file(maps_path).readlines()
    for line in lines:
        k, v = line.split()
        maps[k] = v
    return maps


def write_maps(maps):
    maps_path = conf.pages['maps']
    maps = ["%s %s\n" % (k, v) for k, v in maps.items()]
    file(maps_path, 'w').writelines(maps)


def update_content_url(project, infos):
    verify_input(infos)
    maps = read_maps()
    new = False
    if project not in maps:
        new = True
    maps[project] = infos['url']
    write_maps(maps)
    return new


def delete_content_url(project):
    maps = read_maps()
    if project not in maps:
        raise PageNotFound()
    del maps[project]
    write_maps(maps)
    return True


def get_content_url(project):
    maps = read_maps()
    if project not in maps:
        raise PageNotFound()
    return maps[project]
