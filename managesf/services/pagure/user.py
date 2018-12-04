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


logger = logging.getLogger(__name__)


class PagureUserManager(base.UserManager):
    """User management"""

    def __init__(self, plugin):
        super(PagureUserManager, self).__init__(plugin)
        # Set sql access to add users directly
        db_uri = 'mysql+pymysql://%s:%s@%s/%s?charset=utf8' % (
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
            Column('user', Unicode),
            Column('fullname', Unicode),
            Column('default_email', Unicode),
            Column('created', DateTime),
            Column('updated_on', DateTime),
        )

    def sql_execute(self, stm):
        # SQL session execute wrappper
        logger.debug("Pagure sql: [%s]" % stm)
        try:
            self.sql_session.execute(stm)
            self.sql_session.commit()
        except Exception as e:
            logger.error(u"Pagure SQL failed %s [%s]" % (e, stm))
            self.sql_session.rollback()

    def get_user(self, username):
        stm = self.users.select().where(self.users.c.user == username)
        return self.sql_session.execute(stm).fetchone()

    def create_update_user(self, userid, email, fullname):
        # Use SQL instead of API to force userid
        if self.get_user(userid):
            values = {'updated_on': datetime.datetime.now()}
            if email:
                values['default_email'] = email
            if fullname:
                values['fullname'] = fullname

            stm = self.users.update(). \
                where(self.users.c.id == userid). \
                values(**values)
        else:
            stm = self.users.insert().values(
                id=userid,
                created_at=datetime.datetime.now(),
                default_email=email,
                fullname=fullname
            )
        self.sql_execute(stm)

    def create(self, username, email, full_name, ssh_keys=None, cauth_id=None):
        cauth_id = int(cauth_id)
        self.create_update_user(cauth_id, email, full_name)
        logger.info(u'[%s] uid=%d username=%s created' % (
            self.plugin.service_name, cauth_id, username))
        return cauth_id

    def update(self, uid, username=None, full_name=None, email=None, **kwargs):
        uid = int(uid)
        self.create_update_user(uid, email, full_name)
        logger.info(u'[%s] uid=%d username=%s fullname=%s email=%s updated' % (
            self.plugin.service_name, uid, username, full_name, email))

    def get(self, username):
        logger.info(u'[%s] get username=%s' % (
            self.plugin.service_name, username))
        return self.get_user(username)

    def delete(self, username):
        logger.info(u'[%s] username=%s deleted' % (
            self.plugin.service_name, username))
        if self.get_user(username):
            stm = self.users.delete().where(self.users.c.username == username)
            self.sql_execute(stm)
