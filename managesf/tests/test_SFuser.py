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

import os

from unittest import TestCase

from managesf.controllers import SFuser
from managesf.tests import dummy_conf


class SFuserController(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        SFuser.model.conf = cls.conf

    def setUp(self):
        SFuser.model.init_model()

    def tearDown(self):
        os.unlink(self.conf.sqlalchemy['url'][len('sqlite:///'):])

    def test_create(self):
        u = SFuser.SFUserManager()
        id = u.create(username=u'SpongeBob',
                      email='SquarePants',
                      fullname=u'Sp. Sq.',
                      cauth_id=17)
        self.assertEqual(str(id),
                         SFuser.crud.get(username=u'SpongeBob').get('id'))
        # recreating the same user returns the same id
        id1 = u.create(username=u'SpongeBob',
                       email='SquarePants',
                       fullname=u'Sp. Sq.',
                       cauth_id=17)
        self.assertEqual(str(id1),
                         str(id))
        # if cauth_id is reset, it is updated
        id2 = u.create(username=u'SpongeBob',
                       email='SquarePants',
                       fullname=u'Sp. Sq.',
                       cauth_id=24)
        self.assertEqual(str(id2),
                         str(id))
        self.assertEqual('24',
                         SFuser.crud.get(id2).get('cauth_id'))
        # cauth_id acts as Authoritah
        id3 = u.create(username=u'Jake',
                       email='the Dog',
                       fullname=u'J. the Dog',
                       cauth_id=24)
        self.assertEqual(str(id3),
                         str(id))
        self.assertEqual('Jake',
                         SFuser.crud.get(id3).get('username'))
        self.assertEqual('the Dog',
                         SFuser.crud.get(id3).get('email'))
        self.assertEqual('J. the Dog',
                         SFuser.crud.get(id3).get('fullname'))
        # create another user, default cauth_id is -1
        id4 = u.create(username=u'Finn',
                       email='the Human',
                       fullname=u'F. The Human')
        self.assertTrue(str(id4) != str(id))
        self.assertEqual('-1',
                         SFuser.crud.get(id4).get('cauth_id'))
        # create another user, make sure it does not update Finn
        id5 = u.create(username=u'Bonnibel',
                       email='Bubblegum',
                       fullname=u'Princess Bubblegum')
        self.assertTrue(str(id4) != str(id5))

    def test_get(self):
        u = SFuser.SFUserManager()
        u.create(username=u'Bonnibel',
                 email='Bubblegum',
                 fullname=u'Princess Bubblegum')
        u.create(username=u'Finn',
                 email='the Human',
                 fullname=u'F. The Human')
        id = u.create(username=u'Jake',
                      email='the Dog',
                      fullname=u'J. the Dog',
                      cauth_id=24)
        self.assertEqual('Bonnibel',
                         u.get(username=u'Bonnibel')['username'])
        self.assertEqual('Bubblegum',
                         u.get(username=u'Bonnibel',
                               fullname=u'Princess Bubblegum')['email'])
        self.assertEqual('Finn',
                         u.get(email='the Human')['username'])
        self.assertEqual('the Human',
                         u.get(email='the Human')['email'])
        self.assertEqual('Jake',
                         u.get(fullname=u'J. the Dog')['username'])
        self.assertEqual('the Dog',
                         u.get(fullname=u'J. the Dog')['email'])
        self.assertEqual('Jake',
                         u.get(cauth_id=24)['username'])
        self.assertEqual('Jake',
                         u.get(id)['username'])
        self.assertEqual({},
                         u.get(username=u'BMO'))
        self.assertRaises(KeyError,
                          u.get, cauth_id=-1)

    def test_all(self):
        u = SFuser.SFUserManager()
        u.create(username=u'Bonnibel',
                 email='Bubblegum',
                 fullname=u'Princess Bubblegum')
        u.create(username=u'Finn',
                 email='the Human',
                 fullname=u'F. The Human')
        u.create(username=u'Jake',
                 email='the Dog',
                 fullname=u'J. the Dog',
                 cauth_id=24)
        u.create(username=u'Gunther',
                 email='the Penguin',
                 fullname=u'Orgalorg the Destroyer')
        self.assertEqual(4,
                         len(u.all()))

    def test_update(self):
        u = SFuser.SFUserManager()
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum')
        bonnibel = u.get(pb)
        # updating a non existing user does nothing
        self.assertEqual(None,
                         u.update(pb + 2))
        u.update(pb, username=u'Marceline')
        self.assertEqual('Marceline', u.get(pb)['username'])
        u.update(pb, email='The Vampire')
        self.assertEqual('The Vampire', u.get(pb)['email'])
        u.update(pb, fullname=u'M the V')
        self.assertEqual('M the V', u.get(pb)['fullname'])
        u.update(pb, username=u'Bonnibel',
                 email='Bubblegum', fullname=u'Princess Bubblegum')
        self.assertEqual(bonnibel,
                         u.get(pb))

    def test_reset_cauth_id(self):
        u = SFuser.SFUserManager()
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum',
                      cauth_id=23)
        bonnibel = u.get(pb)
        self.assertEqual('23',
                         bonnibel['cauth_id'])
        u.reset_cauth_id(pb, 42)
        bonnibel = u.get(pb)
        self.assertEqual('42',
                         bonnibel['cauth_id'])

    def test_delete(self):
        u = SFuser.SFUserManager()
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum',
                      cauth_id=23)
        u.delete(pb)
        self.assertEqual({},
                         u.get(username=u'Bonnibel'))
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum',
                      cauth_id=23)
        u.delete(username=u'Bonnibel')
        self.assertEqual({},
                         u.get(username=u'Bonnibel'))
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum',
                      cauth_id=23)
        u.delete(email='Bubblegum')
        self.assertEqual({},
                         u.get(username=u'Bonnibel'))
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum',
                      cauth_id=23)
        u.delete(fullname=u'Princess Bubblegum')
        self.assertEqual({},
                         u.get(username=u'Bonnibel'))
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum',
                      cauth_id=23)
        u.delete(cauth_id=23)
        self.assertEqual({},
                         u.get(username=u'Bonnibel'))
        pb = u.create(username=u'Bonnibel',
                      email='Bubblegum',
                      fullname=u'Princess Bubblegum',
                      cauth_id=23)
        self.assertFalse(u.delete(username=u'SusanStrong'))
        u.delete(cauth_id=23, email='Bubblegum')
        self.assertEqual({},
                         u.get(username=u'Bonnibel'))

    def test_unicode(self):
        """create and get a non ascii user"""
        u = SFuser.SFUserManager()
        id = u.create(username=u'七代目火影4lyf',
                      email='datte@bayo',
                      fullname=u'うずまきナルト',
                      cauth_id=999)
        self.assertEqual(u'うずまきナルト',
                         SFuser.crud.get(id=id).get('fullname'))
        by_username = SFuser.crud.get(username=u'七代目火影4lyf')
        self.assertEqual(u'うずまきナルト',
                         by_username.get('fullname'))
