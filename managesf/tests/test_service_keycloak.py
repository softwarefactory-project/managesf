# Copyright (C) 2022  Red Hat <licensing@enovance.com>
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

from unittest import TestCase
from mock import patch

from managesf.services import keycloak


class MockResponse:
    def __init__(
        self, json_data, status_code=200, headers=None
    ):
        self.json_data = json_data
        self.text = json_data
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code > 399:
            raise Exception(self.status_code)

    def json(self):
        return self.json_data


def mocked_requests_delete(*args, **kwargs):
    return MockResponse(None, 204)


def mocked_requests_put(*args, **kwargs):
    return MockResponse(None, 200)


def mocked_requests_post(*args, **kwargs):

    token_url = (
        "https://kc.sftests.com/realms/master/protocol/openid-connect/token")
    create_urls = (
        "https://kc.sftests.com/admin/realms/sf/roles",
        "https://kc.sftests.com/admin/realms/sf/groups",
        )
    if args[0] == token_url:
        return MockResponse({"access_token": "123"})
    elif args[0] in create_urls:
        return MockResponse({}, headers={'Location': 'xxx'})
    return MockResponse(None, 404)


class TestKeycloakService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.kc_session = keycloak.KeycloakRESTAdminSession(
            "https://kc.sftests.com", "password")

    def test_base_url(self):
        self.assertEqual(
            self.kc_session.admin_realm_url,
            "https://kc.sftests.com/admin/realms/sf")

    def test_token_property(self):
        with patch('requests.post', side_effect=mocked_requests_post) as m:
            token = self.kc_session.token
            self.assertEqual(token, "123")
            token = self.kc_session.token
            self.assertEqual(token, "123")
            # Here only on call as we got the cached version of the token
            self.assertEqual(m.call_count, 1)

            # Override the fetched date and remove 61 sec
            self.kc_session._token["fetched_at"] = (
                self.kc_session._token["fetched_at"] - 61)
            token = self.kc_session.token
            # We did a second network call as expected
            self.assertEqual(m.call_count, 2)

    def test_get_groups_to_update(self):
        kc_groups = [
            {'name': 'common_group',
             'id': '1'},
            {'name': 'group_to_delete',
             'id': '2'},
        ]
        sf_groups = {
            'common_group': {'name': 'common_group'},
            'group_to_add': {'name': 'group_to_add'}
        }
        expected_del = ['2', ]
        expected_created = ['group_to_add', ]

        to_delete, to_create = keycloak.get_groups_to_update(
            sf_groups, kc_groups
        )
        self.assertEqual(to_delete, expected_del, to_delete)
        self.assertEqual(to_create, expected_created, to_create)

    def test_get_group_memberships_to_update(self):
        sf_group = {
            'name': 'my_group',
            'members': [
                'common@test.com',
                'to_add@test.com',
            ]
        }
        # case 1: keycloak knows every user
        current_members = [
            {'name': 'to_remove',
             'email': 'to_remove@test.com'},
            {'name': 'common',
             'email': 'common@test.com'},
            ]
        user_ids_by_email = {
            'common@test.com': '1',
            'to_remove@test.com': '2',
            'to_add@test.com': '3',
        }
        expected_del = ['2', ]
        expected_add = ['3', ]
        to_del, to_add = keycloak.get_group_memberships_to_update(
            sf_group, current_members, user_ids_by_email
        )
        self.assertEqual(expected_del, to_del, to_del)
        self.assertEqual(expected_add, to_add, to_add)
        # case 2: the user to add is unknown to keycloak,
        # expected behavior is silent skipping.
        del user_ids_by_email['to_add@test.com']
        expected_add = []
        to_del, to_add = keycloak.get_group_memberships_to_update(
            sf_group, current_members, user_ids_by_email
        )
        self.assertEqual(expected_del, to_del, to_del)
        self.assertEqual(expected_add, to_add, to_add)

    def test_update_roles(self):
        roles_to_create = ['role1', 'role2', 'role3']

        with patch('requests.post', side_effect=mocked_requests_post) as m:
            with patch('requests.get') as g:
                g.return_value = MockResponse({'name': 'xxx'})
                keycloak.update_roles(self.kc_session, roles_to_create)
                self.assertEqual(m.call_count, len(roles_to_create))
                self.assertEqual(g.call_count, len(roles_to_create))

    def test_update_groups(self):
        ids_to_delete = ['a', 'b', 'c']
        groups_to_create = ['new_1', 'new_2']
        with patch('requests.post',
                   side_effect=mocked_requests_post) as m:
            with patch('requests.delete',
                       side_effect=mocked_requests_delete) as d:
                with patch('requests.get') as g:
                    g.return_value = MockResponse({'name': 'xxx'})
                    keycloak.update_groups(
                        self.kc_session, ids_to_delete, groups_to_create,
                        raiseit=True
                    )
        self.assertEqual(m.call_count, len(groups_to_create))
        self.assertEqual(d.call_count, len(ids_to_delete))
        self.assertEqual(g.call_count, len(groups_to_create))

    def test_update_group_memberships(self):
        kc_group_id = 'kakakaka'
        ids_to_remove = ['a', 'b', 'c', 'd']
        ids_to_add = ['x', 'y', 'z']
        with patch('requests.post',
                   side_effect=mocked_requests_post):
            with patch('requests.delete',
                       side_effect=mocked_requests_delete) as d:
                with patch('requests.put',
                           side_effect=mocked_requests_put) as p:
                    keycloak.update_group_memberships(
                        self.kc_session, kc_group_id,
                        ids_to_remove, ids_to_add,
                        raiseit=True)
        self.assertEqual(d.call_count, len(ids_to_remove))
        self.assertEqual(p.call_count, len(ids_to_add))
