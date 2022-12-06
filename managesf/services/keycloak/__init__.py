#
# Copyright (C) 2022 Red Hat
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


import concurrent.futures as futures
import logging
import time
import requests # noqa

logger = logging.getLogger("managesf.services.keycloak")


class KeycloakRESTAdminSession(object):
    def __init__(
        self,
        base_admin_url,
        admin_password,
        realm="sf",
        verify=True
    ):
        self._token = {'token': None, 'fetched_at': 0}
        self.base_admin_url = base_admin_url
        self.admin_password = admin_password
        self.realm = realm
        self.verify = verify
        self.admin_realm_url = (
            self.base_admin_url + "/admin/realms/" + self.realm)

    @property
    def token(self):
        if not (
              self._token['token'] and
              time.time() - self._token['fetched_at'] < 60):
            endpoint = "/realms/master/protocol/openid-connect/token"
            token_url = self.base_admin_url + endpoint
            payload = {
                'username': 'admin',
                'password': self.admin_password,
                'client_id': "admin-cli",
                'grant_type': 'password',
            }
            token_response = requests.post(
                token_url, data=payload, verify=self.verify).json()
            self._token = {
                'token': token_response.get('access_token'),
                'fetched_at': time.time()
            }
        return self._token['token']

    @property
    def headers(self):
        return {'Authorization': 'Bearer ' + self.token}

    def _get(self, url):
        # TODO figure out pagination support/need
        return requests.get(
            url, headers=self.headers, verify=self.verify).json()

    def _delete(self, url):
        return requests.delete(url, headers=self.headers, verify=self.verify)

    def _post(self, url, *args, **kwargs):
        headers = self.headers
        headers.update({'Content-Type': 'application/json'})
        return requests.post(
            url, headers=headers, verify=self.verify, *args, **kwargs)

    def _put(self, url, *args, **kwargs):
        return requests.put(
            url, headers=self.headers, verify=self.verify, *args, **kwargs)

    def get_groups(self):
        return self._get(self.admin_realm_url + "/groups")

    def get_users(self):
        return self._get(self.admin_realm_url + "/users")

    def get_group_members(self, group_id):
        members_url = self.admin_realm_url + "/groups/" + group_id + "/members"
        return self._get(members_url)

    def _response_to_error_dict(self, url, response):
        return {
            'url': url,
            'status_code': response.status_code,
            'headers': response.headers,
            'text': response.text}

    def _usergroup_action(self, action, user_id, group_id):
        url = (
          self.admin_realm_url
          + "/users/" + user_id
          + "/groups/" + group_id
        )
        if action == "add":
            response = self._put(url)
            if response.status_code < 400:
                return True
        elif action == "delete":
            response = self._delete(url)
            if response.status_code == 204:
                return True
        else:
            raise Exception("Unhandled action '%s'" % action)
        raise Exception(
            'Error applying "%s" on %s'
            ' to %s: %r' % (
                action, user_id, group_id,
                self._response_to_error_dict(url, response)))

    def add_user_to_group(self, user_id, group_id):
        return self._usergroup_action("add", user_id, group_id)

    def remove_user_from_group(self, user_id, group_id):
        return self._usergroup_action("delete", user_id, group_id)

    def _create_element(self, element_suffix, json_params):
        url = self.admin_realm_url + element_suffix
        response = self._post(url, json=json_params)
        response.raise_for_status()
        if 'Location' in response.headers:
            return self._get(response.headers['Location'])
        raise Exception(
            'No new resource returned '
            'when creating %r: %r' % (
                json_params, self._response_to_error_dict(url, response))
        )

    def _delete_element(self, element_id, element_suffix):
        url = self.admin_realm_url + element_suffix + element_id
        response = self._delete(url)
        if response.status_code == 204:
            return True
        raise Exception('Error deleting %s: %r' % (
            element_id, self._response_to_error_dict(url, response)))

    def create_group(self, name):
        return self._create_element("/groups", {'name': name})

    def create_role(self, name, fail_if_conflict=False):
        try:
            return self._create_element("/roles", {'name': name})
        except Exception as e:
            if (not fail_if_conflict) and e.response.status_code == 409:
                return True
            raise e

    def delete_group(self, group_id):
        return self._delete_element(group_id, "/groups/")


def get_groups_to_update(sf_groups, current_kc_groups):
    # Computes the differences between groups declared in the resources
    # and existing Keycloak groups.
    # Returns a tuple of
    # - list of group ids to delete from Keycloak
    # - list of group names to create in Keycloak
    # Arguments:
    # sf_groups: groups from the SF resources definition
    # current_kc_groups: groups list as returned from keycloak
    list_new = [sf_groups[x]['name'] for x in sf_groups]
    list_current = [x['name'] for x in current_kc_groups]

    groups_by_name = dict([(x['name'], x['id']) for x in current_kc_groups])

    groups_to_delete = list(set(list_current) - set(list_new))
    groups_to_create = list(set(list_new) - set(list_current))

    ids_to_delete = [groups_by_name[g] for g in groups_to_delete]

    return ids_to_delete, groups_to_create


def get_group_memberships_to_update(
      sf_group, current_members, userids_by_email):
    # Computes members to add/remove from a keycloak group, so that it
    # is in sync with its corresponding group in the resources.
    # Returns: a tuple of:
    # - list of user ids to remove in the Keycloak group
    # - list user ids to add in the Keycloak group
    # Arguments:
    # sf_group: the group info as handled by the resources
    # current_members: Keycloak group members as returned by
    # kc_group_members(kc_group_id)
    # userids_by_email: a dictionary of keycloak user ids ordered by user
    # emails
    new_members = sf_group['members']
    current_members_emails = [x['email'] for x in current_members]

    members_to_remove = list(set(current_members_emails) - set(new_members))
    members_to_add = list(set(new_members) - set(current_members_emails))

    ids_to_remove = []
    ids_to_add = []
    for u in members_to_remove:
        if u in userids_by_email:
            ids_to_remove.append(userids_by_email[u])
        else:
            logger.info("Warning: unknown user '%s' cannot be removed "
                        "from group '%s', this user needs to log in "
                        "at least once to be managed."
                        % (u, sf_group['name']))
    for u in members_to_add:
        if u in userids_by_email:
            ids_to_add.append(userids_by_email[u])
        else:
            logger.info(
                "Warning: unknown user '%s' cannot be added to group '%s', "
                "this user needs to log in at least once to be managed."
                % (u, sf_group['name']))

    return ids_to_remove, ids_to_add


def update_groups(kc_session, ids_to_delete, groups_to_create, raiseit=False):
    with futures.ThreadPoolExecutor(max_workers=10) as executor:
        tasks = {
            executor.submit(kc_session.delete_group, g): g
            for g in ids_to_delete
        }
        for future in futures.as_completed(tasks):
            id_to_delete = tasks[future]
            try:
                future.result()
                logger.info("Group %s deleted" % id_to_delete)
            except Exception as exc:
                if raiseit:
                    raise
                logger.error(
                    "Unable to delete group %s due to %s" % (
                        id_to_delete, exc))

    with futures.ThreadPoolExecutor(max_workers=10) as executor:
        tasks = {
            executor.submit(kc_session.create_group, g): g
            for g in groups_to_create
        }
        for future in futures.as_completed(tasks):
            try:
                future.result()
                grp = tasks[future]
                logger.info("Group %s created" % grp)
            except Exception as exc:
                if raiseit:
                    raise
                logger.error(
                    "Unable to create group %s due to %s" % (grp, exc))


def update_roles(kc_session, roles_to_create, raiseit=False):
    def create_or_fail_silently(role):
        try:
            return kc_session.create_role(role, fail_if_conflict=False)
        except Exception as e:
            if raiseit:
                raise e
            return False
    with futures.ThreadPoolExecutor(max_workers=10) as executor:
        tasks = {
            executor.submit(create_or_fail_silently, r): r
            for r in roles_to_create
        }
        for future in futures.as_completed(tasks):
            try:
                role = tasks[future]
                if future.result():
                    logger.info("Role %s created or already exists" % role)
                else:
                    logger.info("Role %s was skipped" % role)
            except Exception as exc:
                if raiseit:
                    raise
                logger.error(
                    "Unable to create role %s due to %s" % (role, exc))


def update_group_memberships(
        kc_session, kc_group_id, ids_to_remove, ids_to_add, raiseit=False):
    with futures.ThreadPoolExecutor(max_workers=10) as executor:
        tasks = {
            executor.submit(
                kc_session.remove_user_from_group, *(user_id, kc_group_id)
            ): user_id for user_id in ids_to_remove
        }
        for future in futures.as_completed(tasks):
            try:
                if future.result():
                    uid = tasks[future]
                    logger.info("User %s removed from group %s" % (
                        uid, kc_group_id))
            except Exception as exc:
                if raiseit:
                    raise
                logger.error(
                    "Unable to remove user %s from group %s due to %s" % (
                        uid, kc_group_id, exc))

    with futures.ThreadPoolExecutor(max_workers=10) as executor:
        tasks = {
            executor.submit(
                kc_session.add_user_to_group, *(user_id, kc_group_id)
            ): user_id for user_id in ids_to_add}
        for future in futures.as_completed(tasks):
            try:
                if future.result():
                    uid = tasks[future]
                    logger.info("User %s added to group %s" % (
                        uid, kc_group_id))
            except Exception as exc:
                logger.error(
                    "Unable to add user %s to group %s due to %s" % (
                        uid, kc_group_id, exc))
