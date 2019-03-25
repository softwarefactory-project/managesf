#
# Copyright (C) 2018 Red Hat
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
import sys
import json
import shutil
import logging
import argparse
import tempfile
import requests
import subprocess

from contextlib import contextmanager

from pecan import conf
from pecan import configuration

from sfmanager import sfauth

from managesf.model.yamlbkd.engine import SFResourceBackendEngine


@contextmanager
def TemporaryDirectory():
    name = tempfile.mkdtemp()
    try:
        yield name
    finally:
        shutil.rmtree(name)


def read_data_to_validate():
    data = dict(
        [(os.path.join('resources', f),
          open(os.path.join('resources', f)).read())
         for f in os.listdir('resources')
            if f.endswith('.yaml') or f.endswith('.yml')])
    return data


def is_resources_changes():
    head_sha = subprocess.check_output(
        ["git", "--no-pager", "log", "--no-merges",
         "--format='%H'", "-n", "1", "HEAD"]).strip()
    head_resources_sha = subprocess.check_output(
        ["git", "--no-pager", "log", "--no-merges",
         "--format='%H'", "-n", "1", "HEAD", "--", "resources"]).strip()
    return head_sha == head_resources_sha


def build_auth_cookie(remote_gateway):
    cookie = sfauth.get_cookie(
        remote_gateway, username='SF_SERVICE_USER',
        password=open('.service_user_password').read().strip())
    return cookie


def read_repo_to_validate():
    if not os.path.isdir('.git') or not os.path.isdir('resources'):
        print("Current workding directory must the config repository "
              "to validate")
        sys.exit(1)
    if not is_resources_changes():
        print("Nothing to validate on the resources")
        sys.exit(0)
    head_commit_msg = subprocess.check_output(
        ["git", "log", "-1", "--no-merges"])
    print(head_commit_msg)
    structured_data = read_data_to_validate()
    return structured_data, head_commit_msg


def display_warnings(logs, head_commit_msg):
    if "is going to be deleted" in " ".join(logs):
        if "sf-resources: allow-delete" not in head_commit_msg:
            print(
                "\n"
                "Resources deletion(s) have been detected.\n"
                "The commit msg tag: 'sf-resources: allow-delete' has not "
                "been detected.\n"
                "The change won't be validated until you include the "
                "tag 'sf-resources: allow-delete' in the commit message.")
            sys.exit(1)
    if "sf-resources: skip-apply" in " ".join(logs):
        print(
            "\n"
            "The commit msg tag: 'sf-resources: skip-apply' has been "
            "detected.\n"
            "The approval of this patch won't trigger the creation of "
            "the resources above.\n"
            "The purpose of this commit is usually to re-sync "
            "config/resources with the reality.")


def cli():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--cache-dir", default="/var/lib/software-factory/managesf-resources")
    p.add_argument(
        "--managesf-config", default="/etc/managesf/config.py")
    p.add_argument(
        "--zuul-commit", default='master',
        help="Reference of the commit to apply")
    p.add_argument(
        "--zuul-prev-commit", default='master^1',
        help="Reference of the previous commit applied")
    p.add_argument(
        "--prev-yaml",
        help="Path to the previous yaml (direct-apply)")
    p.add_argument(
        "--new-yaml",
        help="Path to the new yaml (direct-apply)")
    p.add_argument(
        "--log-output", help="Engine logs output file path")
    p.add_argument(
        "--remote-gateway", help="URL to the remote SF")
    p.add_argument("--debug", action="store_true")
    p.add_argument(
        "action", choices=[
            "read", "validate", "remote-validate", "apply", "direct-apply"])
    args = p.parse_args()

    kwargs = {}
    if args.log_output:
        kwargs.update({'filename': args.log_output})

    logging.basicConfig(
        format='%(asctime)s %(levelname)-5.5s %(name)s - %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO,
        **kwargs)

    if not os.path.isdir(os.path.expanduser(args.cache_dir)):
        os.makedirs(os.path.expanduser(args.cache_dir))

    if args.action not in ['remote-validate']:
        configuration.set_config(args.managesf_config)
        engine = SFResourceBackendEngine(
            os.path.join(args.cache_dir, args.action),
            conf.resources.subdir)

    if args.action == "read":
        raw = engine.get(
            conf.resources.master_repo, 'master')
        print(json.dumps(raw, indent=2, sort_keys=True))

    if args.action == "validate":
        structured_data, head_commit_msg = read_repo_to_validate()
        status, logs = engine.validate_from_structured_data(
            conf.resources.master_repo, 'master', structured_data)
        print("")
        print(
            "=== Resources actions list that will apply once patch merged ===")
        print('')
        for action_log in logs:
            print(action_log)
        if not status:
            print("Resource modifications validation failed")
            sys.exit(1)
        display_warnings(logs, head_commit_msg)

    if args.action == "apply":
        if 'ZUUL_COMMIT' in os.environ:
            print("Read ZUUL_COMMIT from environment: %s" % (
                os.environ['ZUUL_COMMIT']))
            args.zuul_commit = os.environ['ZUUL_COMMIT']
        with TemporaryDirectory() as dpath:
            subprocess.call(
                ["git", "clone", conf.resources.master_repo, dpath])
            os.chdir(dpath)
            print("Checkout at ZUUL COMMIT: %s" % args.zuul_commit)
            subprocess.call(
                ["git", "checkout", args.zuul_commit])
            commit_range = "%s..%s" % (args.zuul_prev_commit, args.zuul_commit)
            head_commit_msg = subprocess.check_output(
                ["git", "log", commit_range, "--no-merges"])
            print(head_commit_msg)
            status, logs = engine.apply(
                conf.resources.master_repo, args.zuul_prev_commit,
                dpath, args.zuul_commit)
            print("")
            print(
                "=== Resources actions ===")
            print('')
            for action_log in logs:
                print(action_log)
            if not status:
                print("Resource apply failed")
                sys.exit(1)

    if args.action == "direct-apply":
        if not args.prev_yaml or not args.new_yaml:
            print("Not prev and new yaml. Unable to compute a diff.")
            sys.exit(1)
        status, logs = engine.direct_apply(
            open(args.prev_yaml).read(), open(args.new_yaml).read())
        print("")
        print(
            "=== Resources actions ===")
        print('')
        for action_log in logs:
            print(action_log)
        if not status:
            print("Resource apply failed")
            sys.exit(1)

    if args.action == "remote-validate":
        if not args.remote_gateway:
            print("Need a remote SF gateway URL")
            sys.exit(1)
        if not os.path.isfile('.service_user_password'):
            print("Unable to find .service_user_password")
            sys.exit(1)
        structured_data, head_commit_msg = read_repo_to_validate()
        print("=== Remote validation on %s ===" % args.remote_gateway)
        pubtkt_cookie = build_auth_cookie(args.remote_gateway)
        cookies = {'auth_pubtkt': pubtkt_cookie}
        headers = {'X-Remote-User': "SF_SERVICE_USER"}
        ret = requests.post(
            args.remote_gateway + '/manage/v2/resources/',
            headers=headers, cookies=cookies,
            json={'data': structured_data})
        logs = ret.json()
        print("")
        print(
            "=== Resources actions list that will apply once patch merged ===")
        print('')
        for action_log in logs:
            print(action_log)
        if ret.status_code != 200:
            print("Resource modifications validation failed")
            sys.exit(1)
        display_warnings(logs, head_commit_msg)
