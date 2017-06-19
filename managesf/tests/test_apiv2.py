# Copyright (C) 2017 Red Hat
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


import json
from unittest import TestCase

from managesf.api.v2 import base
from managesf.tests import dummy_conf


class TestAPIv2Service(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

        class DummyService(base.BaseService):
            _config_section = "DummyService"
            service_name = "dummy service"

        cls.service = DummyService(cls.conf)

    @classmethod
    def tearDownClass(cls):
        pass

    def test_baseService(self):
        """Test loading configuration at service instantiation"""
        self.assertEqual(self.conf.DummyService['dummy_opt1'],
                         self.service.conf.get('dummy_opt1'))


class DummyCRUD(base.BaseCRUDManager):
    def __init__(self):
        super(DummyCRUD, self).__init__()
        self.ordering_options = ['a', 'b']

    @base.paginate
    def get(self, **kwargs):
        return [kwargs, ], 1


class TestAPIv2CRUDManager(TestCase):
    @classmethod
    def setupClass(cls):
        cls.crud = DummyCRUD()

    def test_CRUD_get_default_params(self):
        """Test that skip, limit and order_by params defaults are set"""
        self.assertDictEqual({'skip': 0, 'limit': 25, 'order_by': 'a'},
                             self.crud.get()['results'][0])
        self.assertDictEqual({'skip': 15, 'limit': 25, 'order_by': 'a'},
                             self.crud.get(skip=15)['results'][0])
        self.assertDictEqual({'skip': 0, 'limit': 50, 'order_by': 'a'},
                             self.crud.get(limit=50)['results'][0])
        self.assertDictEqual({'skip': 0, 'limit': 25, 'order_by': 'b'},
                             self.crud.get(order_by='b')['results'][0])

    def test_CRUD_get_bad_order_by(self):
        """Test that a bad 'order_by' value is caught"""
        self.assertRaisesRegexp(ValueError,
                                'valid ones are: a, b',
                                self.crud.get, order_by='WRONG')


class TestAPIv2Paginate(TestCase):
    def test_paginate_errors(self):
        """Test detection of incorrect parameter values"""
        def f(**kwargs):
            return range(50), 50
        d = DummyCRUD()
        self.assertRaises(ValueError,
                          base.paginate(f), d, skip='a')
        self.assertRaises(ValueError,
                          base.paginate(f), d, limit='a')
        self.assertRaises(ValueError,
                          base.paginate(f), d, skip=-7)
        self.assertRaises(ValueError,
                          base.paginate(f), d, limit=-2)

    def test_paginate(self):
        """Test result pagination decorator"""
        skipped, total = 0, 50
        d = DummyCRUD()

        def f(*args, **kwargs):
            return range(total), total
        expected = {'total': total,
                    'skipped': skipped,
                    'limit': 25,
                    'results': range(25)}
        self.assertDictEqual(expected,
                             base.paginate(f)(d, skip=skipped))
        skipped = 10
        expected = {'total': total,
                    'skipped': skipped,
                    'limit': 15,
                    'results': range(10, 25)}
        self.assertDictEqual(expected,
                             base.paginate(f)(d, skip=skipped,
                                              limit=15))
        skipped = 0
        expected = {'total': total,
                    'skipped': skipped,
                    'limit': 100,
                    'results': range(total)}
        self.assertDictEqual(expected,
                             base.paginate(f)(d, skip=skipped,
                                              limit=100))
        skipped = 0
        # function does not return total

        def f(*args, **kwargs):
            return range(total)

        expected = {'total': total,
                    'skipped': skipped,
                    'limit': 10,
                    'results': range(0, 10)}
        self.assertDictEqual(expected,
                             base.paginate(f)(d, skip=skipped,
                                              limit=10))


class DummyData(base.V2Data):
    def __init__(self, arg1, arg2, arg3):
        self.arg1 = arg1
        self.arg2 = arg2
        self.arg3 = arg3

    def to_dict(self):
        return {'arg1': self.arg1,
                'a list of stuff': [self.arg2, self.arg3],
                'a dict of stuff': {'a': self.arg1}}


class TestAPIv2DataSerialization(TestCase):
    def test_V2DataObject_JSON_serialization(self):
        """Test that V2Data-type objects get JSON serialized correctly"""
        d = DummyData('a', 'b', 'c')
        json_d = json.dumps(d, cls=base.V2DataJSONEncoder)
        dict_d = json.loads(json_d)
        self.assertDictEqual({'arg1': 'a',
                              'a list of stuff': ['b', 'c'],
                              'a dict of stuff': {'a': 'a'}},
                             dict_d)

    def test_V2DataObject_JSON_serialization_nested(self):
        """Test that V2Data-type nested objects get serialized correctly"""
        d = DummyData('a', 'b', 'c')
        e = DummyData(d, 'f', 'g')
        json_e = json.dumps(e, cls=base.V2DataJSONEncoder)
        dict_e = json.loads(json_e)
        self.assertDictEqual({'arg1': d.to_dict(),
                              'a list of stuff': ['f', 'g'],
                              'a dict of stuff': {'a': d.to_dict()}},
                             dict_e)
