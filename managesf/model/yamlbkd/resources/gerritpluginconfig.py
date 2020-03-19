#
# Copyright (c) 2020 Red Hat, Inc.
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

import os
import re
import tempfile
import logging

from git.config import GitConfigParser

from managesf.model.yamlbkd.resource import BaseResource

logger = logging.getLogger(__name__)


class GerritPluginConfigOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new

    def extra_validations(self, **kwargs):
        logs = []
        plugin_config = kwargs['file']
        name = kwargs['name']

        fd, path = tempfile.mkstemp()
        os.close(fd)
        open(path, 'w').write(plugin_config)
        # Validate the file has the right format
        try:
            c = GitConfigParser(path)
            c.read()
        except Exception as e:
            logger.exception("GitConfigParser failed %s" % e)
            logs.append(str(e))
        finally:
            os.unlink(path)
        if not all([re.match('plugin "[^ ]+"',
                             section) for section in c.sections()]):
            logs.append('%s: plugin config sections should be in the format '
                        '[plugin "<name-of-plugin>"]' % name)
        return logs


class GerritPluginConfig(BaseResource):

    MODEL_TYPE = 'gerrit-plugin'
    DESCRIPTION = ("The plugin resource is used to store a Gerrit plugin "
                   "config at the project level.")
    MODEL = {
        'name': (
            str,
            '.*',
            False,
            '',
            False,
            "The plugin config name",
        ),
        'file': (
            str,
            '.*',
            True,
            None,
            True,
            "The plugin config content",
        ),
    }
    PRIORITY = 30
    PRIMARY_KEY = 'file'
    CALLBACKS = {
        'update': lambda conf, new, kwargs: [],
        'create': lambda conf, new, kwargs: [],
        'delete': lambda conf, new, kwargs: [],
        'extra_validations': lambda conf, new, kwargs:
            GerritPluginConfigOps(conf, new).extra_validations(**kwargs),
        'get_all': lambda conf, new: ([], {}),
    }

    def should_be_updated(self):
        """"""
        return False
