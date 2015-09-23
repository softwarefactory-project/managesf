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

from gerritlib import gerrit

from managesf.services import base
# from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


class SFGerritRoleManager(base.RoleManager):

    # def is_admin(self, requestor=None):
        # client = self.plugin.get_client()
        # grps = client.get_my_groups_id()
        # admin_id = client.get_group_id('Administrators')
        # if admin_id in grps:
        #     return True
        # return False

    def create(self, requestor, role_name, role_description=None):
        logger.info('[%s] creating group %s' % (self.plugin.service_name,
                                                role_name))
        client = self.plugin.get_client()
        if not role_description:
            role_description = "No description available"
        client.create_group(role_name, role_description)
        # initialize first member, otherwise membership actions won't work
        client.add_group_member(requestor, role_name)

    def delete(self, role_name):
        # from customGerritClient
        g = gerrit.Gerrit(self.plugin.conf['host'],
                          self.plugin._full_conf.admin['name'],
                          keyfile=self.plugin.conf['sshkey_priv_path'])
        logger.info("[%s] Deleting group %s" % (self.plugin.service_name,
                                                role_name))
        grp_id = "select group_id from account_group_names " \
                 "where name=\"%s\"" % role_name
        tables = ['account_group_members',
                  'account_group_members_audit',
                  'account_group_by_id',
                  'account_group_by_id_aud',
                  'account_groups']
        err_msg = "[%s] error while deleting %s: %s"
        for t in tables:
            cmd = 'gerrit gsql -c \'delete from %(table)s where ' \
                  'group_id=(%(grp_id)s)\'' % {'table': t, 'grp_id': grp_id}
            out, err = g._ssh(cmd)
            if err:
                logger.info(err_msg % (self.plugin.service_name,
                                       role_name,
                                       err))
        cmd = 'gerrit gsql -c \'delete from account_group_names ' \
              'where name=\"%s\"' % (role_name)
        out, err = g._ssh(cmd)
        if err:
            logger.info(err_msg % (self.plugin.service_name,
                                   role_name,
                                   err))
