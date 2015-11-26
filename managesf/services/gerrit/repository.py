#!/usr/bin/env python
#
# Copyright (C) 2015 Red Hat <licensing@enovance.com>
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

from managesf.controllers.utils import template
from managesf.services import base
# from managesf.services import exceptions as exc
from managesf.services.gerrit import utils


logger = logging.getLogger(__name__)


class SFGerritRepositoryManager(base.RepositoryManager):

    def create(self, prj_name, prj_desc, upstream, private, ssh_key=None,
               add_branches=False):
        logger.info("[%s] Init project repo: %s" % (self.plugin.service_name,
                                                    prj_name))
        ge = self.plugin.get_client()
        grps = {}
        grps['project-description'] = prj_desc
        grps['core-group-uuid'] = ge.get_group_id("%s-core" % prj_name)
        grps['ptl-group-uuid'] = ge.get_group_id("%s-ptl" % prj_name)
        if private:
            grps['dev-group-uuid'] = ge.get_group_id("%s-dev" % prj_name)
        non_interactive = 'Non-Interactive%20Users'
        grps['non-interactive-users'] = ge.get_group_id(non_interactive)
        grps['core-group'] = "%s-core" % prj_name
        grps['ptl-group'] = "%s-ptl" % prj_name
        if private:
            grps['dev-group'] = "%s-dev" % prj_name
        grepo = utils.GerritRepo(prj_name, self.plugin._full_conf)
        grepo.clone()
        paths = {}

        prefix = ''
        if private:
            prefix = 'private-'
        paths['project.config'] = file(template(prefix +
                                       'project.config')).read() % grps
        paths['groups'] = file(template(prefix + 'groups')).read() % grps
        grepo.push_config(paths)
        if upstream:
            grepo.push_master_from_git_remote(upstream, ssh_key,
                                              add_branches=add_branches)
        paths = {}
        paths['.gitreview'] = file(template('gitreview')).read() % \
            {'gerrit-host': self.plugin.conf['top_domain'],
             'gerrit-host-port': self.plugin.conf['ssh_port'],
             'name': prj_name
             }
        grepo.push_master(paths)
