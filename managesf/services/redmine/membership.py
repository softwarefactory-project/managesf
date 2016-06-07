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

# from redmine.exceptions import ResourceNotFoundError

from managesf.services import base
from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


class RedmineMembershipManager(base.MembershipManager):
    """Membership management"""
    # TODO(mhu)

    def _get_uid(self, username):
        uid = self.plugin.user.get(username=username)
        if not uid:
            uid = self.plugin.user.get(email=username)
        return uid

    def _clean_name(self, name):
        return name.replace('/', '_')


class SFRedmineMembershipManager(RedmineMembershipManager):
    """Management of users memberships in projects."""

    def create(self, requestor, username, project,
               groups, user_is_owner=False, **kwargs):
        """Add user to project groups"""
        rm = self.plugin.get_client()
        project = self._clean_name(project)
        for g in groups:
            if g not in ['ptl-group', 'core-group', 'dev-group']:
                raise exc.UnavailableActionError('Unknown group %s' % g)
        roles = self.plugin.role.get(requestor, project)
        logger.info(u"[%s] %s adding user %s in groups %s from project %s" %
                    (self.plugin.service_name, requestor, username,
                     str(groups), project))
        role_id = []
        # only admin or manager can add manager
        if 'ptl-group' in groups:
            if (not self.plugin.role.is_admin(requestor)) and \
                    ('Manager' not in roles) and (not user_is_owner):
                msg = "[%s] only permitted to admin or project manager"
                logger.info(msg % self.plugin.service_name)
                raise exc.Unauthorized(msg % self.plugin.service_name)
            mgr_role_id = rm.get_role_id('Manager')
            role_id.append(mgr_role_id)
        if ('core-group' in groups) or ('dev-group' in groups):
            if (not self.plugin.role.is_admin(requestor)) and \
                    ('Manager' not in roles) and (not user_is_owner) and \
                    ('Developer' not in roles):
                msg = "[%s] only permitted to admin, Manager, or Developer"
                logger.info(msg % self.plugin.service_name)
                raise exc.Unauthorized(msg % self.plugin.service_name)
            dev_role_id = rm.get_role_id('Developer')
            role_id.append(dev_role_id)
        uid = self._get_uid(username)
        if not uid:
            uid = rm.get_group_id(username)
            if not uid:
                # Corner case we won't fail here.
                # We used to manage uncorrectly project' groups
                # inside redmine where users supposed to be in
                # project group were just assigned a role instead
                # of putting them in a group with an attached role.
                # Here it is pretty sure a group like p1-ptl needs
                # to be added but does not exist on Redmine.
                return
        m = rm.get_project_membership_for_user(project, uid)
        if m:
            roles = rm.get_project_roles_for_user(project, uid)
            role_ids = [rm.get_role_id(u) for u in roles]
            role_ids.extend(role_id)
            rm.update_membership(m, role_ids)
        else:
            memberships = {'user_id': uid, 'role_ids': role_id}
            rm.update_project_membership(project, [memberships])

    def delete(self, requestor, username, project_name, group=None):
        """remove username's membership to group from project_name"""
        rm = self.plugin.get_client()
        project_name = self._clean_name(project_name)
        uid = self._get_uid(username=username)
        if not uid:
            uid = rm.get_group_id(username)
            if not uid:
                # Corner case we won't fail here.
                # We used to manage uncorrectly project' groups
                # inside redmine where users supposed to be in
                # project group were just assigned a role instead
                # of putting them in a group with an attached role.
                # Here it is pretty sure a group like p1-ptl needs
                # to be added but does not exist on Redmine.
                return
        m = rm.get_project_membership_for_user(project_name, uid)
        if not m:
            return None
        user_roles = self.plugin.role.get(requestor, project_name)
        if group is None:
            # delete every group
            if ((not self.plugin.role.is_admin(requestor)) and
                    ('Manager' not in user_roles)):
                msg = u"[%s] Aborted because %s is not admin or Manager"
                logger.debug(msg % (self.plugin.service_name, requestor))
                raise exc.Unauthorized(msg % (self.plugin.service_name,
                                              username))
            rm.delete_membership(m)
        else:
            if group and group not in ['ptl-group',
                                       'core-group',
                                       'dev-group']:
                raise exc.UnavailableActionError("Unknown group %s" % group)
            # Get the role id from requested group name
            if group in ['dev-group', 'core-group']:
                if (not self.plugin.role.is_admin(requestor) and
                   ('Manager' not in user_roles) and
                   ('Developer' not in user_roles)):
                    msg = u"[%s] Aborted because %s is not admin, Manager"
                    msg += u", Developer"
                    logger.debug(msg % (self.plugin.service_name, requestor))
                    raise exc.Unauthorized(msg % (self.plugin.service_name,
                                                  requestor))
                role_id = rm.get_role_id('Developer')
            else:
                if ((not self.plugin.role.is_admin(requestor)) and
                        ('Manager' not in user_roles)):
                    msg = u"[%s] Aborted because %s is not admin or Manager"
                    logger.debug(msg % (self.plugin.service_name, requestor))
                    raise exc.Unauthorized(msg % (self.plugin.service_name,
                                                  requestor))
                role_id = rm.get_role_id('Manager')
            # Get list of current role_ids for this user
            uroles = rm.get_project_roles_for_user(project_name, uid)
            role_ids = [rm.get_role_id(u) for u in uroles]
            # check if requested role is present in the membership roles
            if role_id in role_ids:
                role_ids.remove(role_id)
                # delete te requested role
                rm.update_membership(m, role_ids)
