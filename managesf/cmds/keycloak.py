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


import os
import logging
import argparse

from managesf.model.yamlbkd.engine import SFResourceBackendEngine
from managesf.services import keycloak


def cli():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--cache-dir", default="/var/lib/software-factory/managesf-keycloak")
    p.add_argument(
        "--config-dir", default="/root/config")
    p.add_argument("--kc-api")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--verify", action="store_true")
    p.add_argument(
        "action", choices=["sync-roles"])
    args = p.parse_args()

    logging.basicConfig(
        format='%(asctime)s %(levelname)-5.5s %(name)s - %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO)

    if not os.path.isdir(os.path.expanduser(args.cache_dir)):
        os.makedirs(os.path.expanduser(args.cache_dir))

    kc_admin_password = os.environ.get("KC_ADMIN_PASSWORD")

    if args.action == 'sync-roles':
        engine = SFResourceBackendEngine(
            os.path.join(args.cache_dir, args.action),
            "resources")
        resources = engine.get(
            "file://" + args.config_dir, "master", "notused")
        tenants = resources.get('resources').get('tenants').keys()
        roles = ["%s_zuul_admin" % t for t in tenants]
        kc_session = keycloak.KeycloakRESTAdminSession(
            args.kc_api, kc_admin_password, verify=args.verify)
        keycloak.update_roles(kc_session, roles)
