# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Red Hat, Inc.
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

from managesf.model.yamlbkd.resource import BaseResource

# This is a Test object


class DummyOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new

    def create(self, **kwargs):
        return []

    def delete(self, **kwargs):
        return []

    def update(self, **kwargs):
        return []

    def extra_validations(self, **kwargs):
        return []

    def get_all(self):
        return [], {}


class Dummy(BaseResource):
    MODEL_TYPE = 'dummy'
    MODEL = {
        'namespace': (
            str,
            r'^([a-zA-Z0-9\-_])+$',
            True,
            None,
            False,
            "",
        ),
        'name': (
            str,
            r'^([a-zA-Z0-9\-_])+$',
            False,
            "",
            False,
            "",
        ),
        'description': (
            str,
            r'^([a-zA-Z0-9\-_ ])*$',
            False,
            "",
            True,
            "",
        ),
    }
    PRIMARY_KEY = 'name'
    PRIORITY = 50
    CALLBACKS = {
        'update': lambda conf, new, kwargs:
            DummyOps(conf, new).update(**kwargs),
        'create': lambda conf, new, kwargs:
            DummyOps(conf, new).create(**kwargs),
        'delete': lambda conf, new, kwargs:
            DummyOps(conf, new).delete(**kwargs),
        'extra_validations': lambda conf, new, kwargs:
            DummyOps(conf, new).extra_validations(**kwargs),
        'get_all': lambda conf, new:
            DummyOps(conf, new).get_all(),
    }
