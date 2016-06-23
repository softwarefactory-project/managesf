#!/usr/bin/env python
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


import datetime
import logging
from sqlalchemy import create_engine, orm
from sqlalchemy import Table, Column, Integer, DateTime, Unicode, MetaData

from managesf.services import base
import storyboardclient.openstack.common.apiclient.exceptions as sbexc


logger = logging.getLogger(__name__)


class StoryboardUserManager(base.UserManager):
    """User management"""

    def __init__(self, plugin):
        super(StoryboardUserManager, self).__init__(plugin)
        # Set sql access to add users directly
        db_uri = 'mysql://%s:%s@%s/%s?charset=utf8' % (
            self.plugin.conf['db_user'],
            self.plugin.conf['db_password'],
            self.plugin.conf['db_host'],
            self.plugin.conf['db_name'],
        )
        engine = create_engine(db_uri, echo=False, pool_recycle=600)
        Session = orm.sessionmaker(bind=engine)
        self.sql_session = Session()
        metadata = MetaData()
        self.users = Table(
            'users',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('created_at', DateTime),
            Column('updated_at', DateTime),
            Column('email', Unicode),
            Column('is_staff', Integer),
            Column('is_superuser', Integer),
            Column('last_login', DateTime),
            Column('openid', Unicode),
            Column('full_name', Unicode),
            Column('enable_login', Integer),
        )
        # Use the api client for other operations
        self.client = self.plugin.get_client()

    def sql_execute(self, stm):
        # SQL session execute wrappper
        logger.debug(u"Storyboard sql: [%s]" % unicode(stm))
        try:
            self.sql_session.execute(stm)
            self.sql_session.commit()
        except Exception as e:
            logger.error(u"Storyboard SQL failed %s [%s]" % (e, stm))
            self.sql_session.rollback()

    def get_user(self, userid=None, mail=None):
        # Return user from database
        if mail:
            stm = self.users.select().where(self.users.c.email == mail)
        else:
            stm = self.users.select().where(self.users.c.id == userid)
        return self.sql_session.execute(stm).fetchone()

    def create_update_user(self, userid, email, fullname):
        # Use SQL instead of API to force userid
        if self.get_user(userid):
            values = {'updated_at': datetime.datetime.now()}
            if email:
                values['email'] = email
            if fullname:
                values['full_name'] = fullname

            stm = self.users.update(). \
                where(self.users.c.id == userid). \
                values(**values)
        else:
            if userid == 1:
                superuser = True
            else:
                superuser = False
            stm = self.users.insert().values(
                id=userid,
                created_at=datetime.datetime.now(),
                email=email,
                is_superuser=superuser,
                openid="None",
                full_name=fullname
            )
        self.sql_execute(stm)

    def create_update_user_token(self, userid, username):
        if not username and int(userid) == 1:
            username = "admin"
        user = self.client.users.get(userid)
        try:
            user.user_tokens.create(user_id=userid, access_token=username,
                                    expires_in=315360000)
        except sbexc.Conflict:
            # token already exist
            pass
        return user

    def create(self, username, email, full_name, ssh_keys=None, cauth_id=None):
        cauth_id = int(cauth_id)
        self.create_update_user(cauth_id, email, full_name)
        user = self.create_update_user_token(cauth_id, username)
        logger.info(u'[%s] uid=%d username=%s created %s' % (
            self.plugin.service_name, cauth_id, username, unicode(user)))
        return user.id

    def update(self, uid, username=None, full_name=None, email=None, **kwargs):
        uid = int(uid)
        self.create_update_user(uid, email, full_name)
        if username:
            self.create_update_user_token(uid, username)
        logger.info(u'[%s] uid=%d username=%s fullname=%s email=%s updated' % (
            self.plugin.service_name, uid, username, full_name, email))

    def get(self, mail=None, username=None):
        logger.info(u'[%s] get mail=%s username=%s' % (
            self.plugin.service_name, mail, username))
        return self.get_user(mail=mail)

    def delete(self, email=None, username=None):
        logger.info(u'[%s] delete email=%s username=%s' % (
            self.plugin.service_name, email, username))
        if self.get_user(mail=email):
            stm = self.users.delete().where(self.users.c.email == email)
            self.sql_execute(stm)
