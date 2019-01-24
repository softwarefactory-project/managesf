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

from unittest import TestCase

from managesf.model.yamlbkd.resource import BaseResource
from managesf.model.yamlbkd.resource import ResourceInvalidException
from managesf.model.yamlbkd.resource import ModelInvalidException


class ResourcesTest(TestCase):

    def test_resource_model(self):
        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'key': (str, ".*", False, "string", True, "desc"),
            }
            PRIMARY_KEY = None
            PRIORITY = 10

        self.assertRaises(ModelInvalidException,
                          R1, 'id', {})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
                'key': (str, ".*", False, "string", True, "desc"),
            }
            PRIMARY_KEY = None
            PRIORITY = 10

        r = R1('id', {})
        self.assertEqual(r.resource['name'], 'id')
        r = R1('id', {'name': 'overwritten'})
        self.assertEqual(r.resource['name'], 'id')

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, "[0-9]+", False, "123", True, "Name"),
            }
            PRIMARY_KEY = None
            PRIORITY = 10

        r = R1('id', {})
        self.assertRaises(ResourceInvalidException,
                          r.validate)

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
                'key': (int, None, False, "string", True, "desc"),
            }
            PRIMARY_KEY = 'name'
            PRIORITY = 10

        self.assertRaises(ModelInvalidException,
                          R1, 'id', {})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
                'key': (int, None, False, "string", True, "desc"),
            }
            PRIMARY_KEY = None
            PRIORITY = 10

        self.assertRaises(ModelInvalidException,
                          R1, 'id', {})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'key': (str, '^[A-Z]+$', False, "123", True, "desc"),
                'name': (str, ".*", True, None, False, "desc"),
            }
            PRIMARY_KEY = 'name'
            PRIORITY = 10
        self.assertRaises(ModelInvalidException,
                          R1, 'id', {'name': '123'})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
                'key': (dict, ('.*', '.*'), False, "data", True, "desc"),
            }
            PRIMARY_KEY = 'name'
            PRIORITY = 10
        self.assertRaises(ModelInvalidException,
                          R1, 'id', {'key': {}})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
                'key': (dict, '.*', False, {"key": "value"}, True, "desc"),
            }
            PRIMARY_KEY = 'name'
            PRIORITY = 10
        self.assertRaises(ModelInvalidException,
                          R1, 'id', {'key': {}})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
                'key': (int, None, True, None, True, "desc"),
                'key2': (str, ".+", False, "default", True, "desc"),
                'key3': (list, "[0-9]+", False, [], True, "desc"),
                'key4': (dict, ('[a-z]', r'\d+'), False, {}, True, "desc"),
                'key5': (list, (dict, '.+'), False, [], True, "desc"),
            }
            PRIMARY_KEY = None
            PRIORITY = 10

        res = R1('id', {'key': 1})
        res.validate()
        res.set_defaults()
        resource = res.get_resource()
        self.assertIn('key2', resource)
        self.assertTrue(isinstance(resource['key2'],
                                   str))
        res = R1('id', {'key': 'string'})
        self.assertRaises(ResourceInvalidException,
                          res.validate)
        res = R1('id', {})
        self.assertRaises(ResourceInvalidException,
                          res.validate)
        res = R1('id', {'key': 1, 'extra': 'value'})
        self.assertRaises(ResourceInvalidException,
                          res.validate)
        res = R1('id', {'key': 1,
                        'key3': ['12', '13']})
        res.validate()
        res = R1('id', {'key': 1,
                        'key3': ['12', 'abc']})
        self.assertRaises(ResourceInvalidException,
                          res.validate)
        res = R1('id', {'key': 1,
                        'key3': [
                            '12',
                            {'a1': None}]})
        self.assertRaises(ResourceInvalidException,
                          res.validate)
        res = R1('id', {'key': 1,
                        'key4': {}})
        res.validate()
        res = R1('id', {'key': 1,
                        'key4': {'master': '1234',
                                 'dev': '1234'}})
        res = R1('id', {'key': 1,
                        'key4': {'master': '1234',
                                 'dev': 'abc'}})
        self.assertRaises(ResourceInvalidException,
                          res.validate)
        res = R1('id', {'key': 1,
                        'key5': [
                            'a1',
                            {'a2': None}
                        ]})
        res.validate()
        res = R1('id', {'key': 1,
                        'key5': [
                            'a1',
                            {'a2': None,
                             'morekey': None}
                        ]})
        self.assertRaises(ResourceInvalidException,
                          res.validate)
        res = R1('id', {'key': 1,
                        'key4': {
                            'subk1': '123',
                            'subk2': True,
                            'subk3': 123
                            }})
        res.validate()

    def test_resource_model_callbacks(self):
        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
            }
            PRIORITY = 10
            PRIMARY_KEY = None
            CALLBACKS = {
                'update': NotImplementedError,
                'create': lambda: None,
                'delete': lambda: None,
                'extra_validations': NotImplementedError,
                'get_all': NotImplementedError,
            }
        R1('id', {})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
            }
            PRIORITY = 10
            PRIMARY_KEY = None
            CALLBACKS = {
                'delete': lambda: None,
            }
        self.assertRaises(ModelInvalidException,
                          R1, 'id', {})

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
            }
            PRIMARY_KEY = None
            PRIORITY = 10
            CALLBACKS = {
                'update': NotImplementedError,
                'create': None,
                'delete': lambda: None,
                'extra_validations': NotImplementedError,
                'get_all': NotImplementedError,
            }
        self.assertRaises(ModelInvalidException,
                          R1, 'id', {})

        class Ops(object):
            def create(self, **kwargs):
                return kwargs

        class R1(BaseResource):
            MODEL_TYPE = 'test'
            MODEL = {
                'name': (str, ".*", False, "string", True, "Name"),
            }
            PRIMARY_KEY = None
            PRIORITY = 10
            CALLBACKS = {
                'update': NotImplementedError,
                'create': lambda kwargs: Ops().create(**kwargs),
                'delete': lambda: None,
                'extra_validations': NotImplementedError,
                'get_all': NotImplementedError,
            }
        res = R1('id', {})
        self.assertDictEqual({'arg': 'value'},
                             res.CALLBACKS['create']({'arg': 'value'}))
