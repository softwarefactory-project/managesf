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

from managesf.services import base
from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


class SFGerritMembershipManager(base.MembershipManager):

    def create(self, requestor, user, project, groups, **kwargs):
        """Add user membership to project groups"""
        logger.info("[%s] Add user %s in groups %s for project %s" %
                    (self.plugin.service_name, user, str(groups), project))
        client = self.plugin.get_client()
        for g in groups:
            if g not in ['ptl-group', 'core-group', 'dev-group']:
                raise exc.UnavailableActionError('Unknown group %s' % g)
        grps = client.get_user_groups_id(requestor)
        ptl_gid = client.get_group_id("%s-ptl" % project)
        core_gid = client.get_group_id("%s-core" % project)
        # only PTL can add user to ptl group
        msg = "[%s] %s belongs to groups %s - PTL GID is %s, core GID is %s"
        logger.info(msg % (self.plugin.service_name, requestor,
                           str(grps), ptl_gid, core_gid))
        logger.info('%s is admin: %s' % (requestor,
                                         self.plugin.role.is_admin(requestor)))
        if 'ptl-group' in groups:
            if ((ptl_gid not in grps) and
                    (not self.plugin.role.is_admin(requestor))):
                msg = "[%s] %s is not ptl or admin"
                logger.info(msg % (self.plugin.service_name, requestor))
                raise exc.Unauthorized(msg % (self.plugin.service_name,
                                              requestor))
            ptl = "%s-ptl" % project
            client.add_group_member(user, ptl)
        if 'core-group' in groups:
            if (core_gid not in grps) and (ptl_gid not in grps) and \
               (not self.plugin.role.is_admin(requestor)):
                msg = "[%s] %s is not core, ptl, or admin"
                logger.info(msg % (self.plugin.service_name, requestor))
                raise exc.Unauthorized(msg % (self.plugin.service_name,
                                              requestor))
            core = "%s-core" % project
            client.add_group_member(user, core)
        if 'dev-group' in groups:
            dev = "%s-dev" % project
            if client.group_exists(dev):
                dev_gid = client.get_group_id(dev)
                if (core_gid not in grps) and (ptl_gid not in grps) and \
                   (dev_gid not in grps) and \
                   (not self.plugin.role.is_admin(requestor)):
                    msg = "[%s] %s is not ptl, core, dev, admin"
                    logger.info(msg % (self.plugin.service_name, requestor))
                    raise exc.Unauthorized(msg % (self.plugin.service_name,
                                                  requestor))
                client.add_group_member(user, dev)

    def delete(self, requestor, user, project, group):
        if group:
            if group not in ['ptl-group', 'core-group', 'dev-group']:
                raise exc.UnavailableActionError("Unknown group %s" % group)
            groups = [group]
        else:
            groups = ['ptl-group', 'core-group', 'dev-group']

        logger.info("[%s] Remove user %s from groups %s for project %s" %
                    (self.plugin.service_name, user, groups, project))

        client = self.plugin.get_client()
        core_gid = client.get_group_id("%s-core" % project)
        ptl_gid = client.get_group_id("%s-ptl" % project)
        # get the groups of the current user
        grps = client.get_user_groups_id(requestor)
        dev = "%s-dev" % project
        # delete dev group if requested
        if ('dev-group' in groups) and client.group_exists(dev):
            dev_gid = client.get_group_id(dev)
            if (dev_gid not in grps) and (core_gid not in grps) and \
               (ptl_gid not in grps) and \
               (not self.plugin.role.is_admin(requestor)):
                msg = "[%s] %s is not dev, core, ptl, or admin"
                logger.info(msg % (self.plugin.service_name,
                                   requestor))
                raise exc.Unauthorized(msg % (self.plugin.service_name,
                                              requestor))
            dev_mid = client.get_group_member_id(dev_gid, mail=user)
            # not found ? try by user
            if not dev_mid:
                dev_mid = client.get_group_member_id(dev_gid, username=user)
            if dev_mid:
                client.delete_group_member(dev_gid, dev_mid)

        # delete ptl group if requested
        if 'ptl-group' in groups:
            if (ptl_gid not in grps) and \
               (not self.plugin.role.is_admin(requestor)):
                msg = "[%s] %s is not ptl, admin"
                logger.info(msg % (self.plugin.service_name,
                                   requestor))
                raise exc.Unauthorized(msg % (self.plugin.service_name,
                                              requestor))
            ptl_mid = client.get_group_member_id(ptl_gid, mail=user)
            if not ptl_mid:
                ptl_mid = client.get_group_member_id(ptl_gid, username=user)
            if ptl_mid:
                client.delete_group_member(ptl_gid, ptl_mid)

        # delete core group if requested
        if 'core-group' in groups:
            if (ptl_gid not in grps) and (core_gid not in grps) and \
               (not self.plugin.role.is_admin(requestor)):
                msg = "[%s] %s is not core, ptl, admin"
                logger.info(msg % (self.plugin.service_name,
                                   requestor))
                raise exc.Unauthorized(msg % (self.plugin.service_name,
                                              requestor))
            core_mid = client.get_group_member_id(core_gid, mail=user)
            if core_mid:
                client.delete_group_member(core_gid, core_mid)
