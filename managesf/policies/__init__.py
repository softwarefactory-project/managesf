#
# Copyright (C) 2016 Red Hat
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
# -*- coding: utf-8 -*-


import itertools


from managesf.policies import base
from managesf.policies import backup
from managesf.policies import config
from managesf.policies import group
from managesf.policies import hooks
from managesf.policies import htpasswd
# from managesf.policies import introspection
from managesf.policies import localuser
from managesf.policies import membership
from managesf.policies import pages
from managesf.policies import project
from managesf.policies import services_users
from managesf.policies import tests
from managesf.policies import resources
from managesf.policies import job
from managesf.policies import node


def list_rules():
    return itertools.chain(
        base.list_rules(),
        backup.list_rules(),
        project.list_rules(),
        membership.list_rules(),
        group.list_rules(),
        pages.list_rules(),
        localuser.list_rules(),
        services_users.list_rules(),
        htpasswd.list_rules(),
        hooks.list_rules(),
        tests.list_rules(),
        config.list_rules(),
        resources.list_rules(),
        job.list_rules(),
        node.list_rules(), )
# introspection.list_rules(),
