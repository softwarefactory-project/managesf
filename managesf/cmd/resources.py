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
import tempfile
import subprocess

from contextlib import contextmanager

from pecan import conf
from pecan import configuration


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


def cli():
    import argparse
    from managesf.model.yamlbkd.engine import SFResourceBackendEngine

    p = argparse.ArgumentParser()
    p.add_argument(
        "--cache-dir", default="/var/lib/software-factory/managesf-resources")
    p.add_argument(
        "--managesf-config", default="/etc/managesf/config.py")
    p.add_argument(
        "--zuul-commit",
        help="SHA of the commit we are going to apply")
    p.add_argument("--debug", action="store_true")
    p.add_argument("action", choices=["read", "validate", "apply"])
    args = p.parse_args()

    logging.basicConfig(
        format='%(asctime)s %(levelname)-5.5s %(name)s - %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO)

    configuration.set_config(args.managesf_config)

    if not os.path.isdir(os.path.expanduser(args.cache_dir)):
        os.makedirs(os.path.expanduser(args.cache_dir))

    engine = SFResourceBackendEngine(
        os.path.join(args.cache_dir, args.action),
        conf.resources.subdir)

    if args.action == "read":
        raw = engine.get(
            conf.resources.master_repo, 'master')
        print(json.dumps(raw, indent=2, sort_keys=True))

    if args.action == "validate":
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

    if args.action == "apply":
        if not args.zuul_commit:
            print("ZUUL_COMMIT not set. Skip processing.")
            sys.exit(0)
        with TemporaryDirectory() as dpath:
            subprocess.call(
                ["git", "clone", conf.resources.master_repo, dpath])
            os.chdir(dpath)
            print("Checkout at ZUUL COMMIT: %s" % args.zuul_commit)
            subprocess.call(
                ["git", "checkout", args.zuul_commit])
            head_commit_msg = subprocess.check_output(
                ["git", "log", "-1", "--no-merges"])
            print(head_commit_msg)
            if not is_resources_changes():
                print("Nothing to validate on the resources")
                sys.exit(0)
            status, logs = engine.apply(
                conf.resources.master_repo, 'master^1',
                dpath, 'master')
            print("")
            print(
                "=== Resources actions ===")
            print('')
            for action_log in logs:
                print(action_log)
            if not status:
                print("Resource apply failed")
                sys.exit(1)
