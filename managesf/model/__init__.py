#
# Copyright (c) 2015 Red Hat, Inc.
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

import logging

from pecan import conf  # noqa
from sqlalchemy import create_engine, Column, String, Unicode, UnicodeText
from sqlalchemy import Boolean, Integer, exc, event
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from sqlalchemy.ext.declarative import declarative_base
from contextlib import contextmanager


Base = declarative_base()
engine = None


logger = logging.getLogger(__name__)


def row2dict(row):
    ret = {}
    for column in row.__table__.columns:
        ret[column.name] = getattr(row, column.name)
        # TODO: Fix test and remove bellow hack!
        if not isinstance(ret[column.name], (str, bytes)) and \
           not isinstance(ret[column.name], bool):
            ret[column.name] = str(ret[column.name])
    return ret


class User(Base):
    __tablename__ = 'users'
    username = Column(Unicode(255), primary_key=True)
    fullname = Column(Unicode(255), nullable=False)
    email = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    sshkey = Column(String(1023), nullable=True)


def checkout_listener(dbapi_con, con_record, con_proxy):
    try:
        try:
            dbapi_con.ping(False)
        except TypeError:
            dbapi_con.ping()
    except dbapi_con.OperationalError as e:
        if e.args[0] in (2006,   # MySQL server has gone away
                         2013,   # Lost connection to server during query
                         2055):  # Lost connection to server
            # caught by pool, which will retry with a new connection
            raise exc.DisconnectionError()
        else:
            raise


class SFUser(Base):
    __tablename__ = 'SF_USERS'
    id = Column(Integer(), primary_key=True)
    username = Column(Unicode(255), nullable=False, unique=True)
    fullname = Column(Unicode(255), nullable=True)
    # Gerrit requires email unicity
    email = Column(String(255), nullable=False, unique=True)
    cauth_id = Column(Integer(), nullable=False)
    idp_sync = Column(Boolean(), default=True)


class SFUserServiceMapping(Base):
    __tablename__ = 'SF_USERS_SERVICES_MAPPING'
    # needed for constraint definition, not actually used
    id = Column(Integer(), primary_key=True)
    sf_user_id = Column(Integer(), ForeignKey('SF_USERS.id'),
                        nullable=False)
    # will simply store the plugin name
    service = Column(String(255), nullable=False)
    # for extended future compatibility, don't limit to integers
    service_user_id = Column(String(255), nullable=False)
    __table_args__ = (UniqueConstraint('sf_user_id',
                                       'service',
                                       'service_user_id',
                                       name='unique_service_user'), )


class SFUserCRUD:
    def set_service_mapping(self, sf_user_id, service, service_user_id):
        with session_scope() as session:
            r = SFUserServiceMapping(sf_user_id=sf_user_id,
                                     service=service,
                                     service_user_id=service_user_id)
            session.add(r)

    def get_service_mapping(self, service, sf_user_id):
        with session_scope() as session:
            filtering = {'service': service,
                         'sf_user_id': sf_user_id}
            try:
                r = session.query(SFUserServiceMapping).filter_by(**filtering)
                return r.one().service_user_id
            except MultipleResultsFound:
                msg = 'Too many mappings for user #%s on service %s'
                raise KeyError(msg % (sf_user_id, service))
            except NoResultFound:
                return None

    def get_user_mapping(self, service, service_user_id):
        with session_scope() as session:
            filtering = {'service': service,
                         'service_user_id': service_user_id}
            try:
                r = session.query(SFUserServiceMapping).filter_by(**filtering)
                return r.one().service_user_id
            except MultipleResultsFound:
                msg = 'Too many mappings for service %s\'s user #%s'
                raise KeyError(msg % (service_user_id, service))
            except NoResultFound:
                return None

    def delete_service_mapping(self, sf_user_id,
                               service=None, service_user_id=None):
        with session_scope() as session:
            filtering = {'sf_user_id': sf_user_id}
            if service:
                filtering['service'] = service
            if service_user_id:
                filtering['service_user_id'] = service_user_id
            m = session.query(SFUserServiceMapping).filter_by(**filtering)
            m.delete(synchronize_session=False)

    def get(self, id=None, username=None, email=None,
            fullname=None, cauth_id=None):
        with session_scope() as session:
            if (id or username or email or fullname or cauth_id):
                filtering = {}
                if id:
                    filtering['id'] = id
                if username:
                    filtering['username'] = username
                if email:
                    filtering['email'] = email
                if fullname:
                    filtering['fullname'] = fullname
                if cauth_id:
                    filtering['cauth_id'] = cauth_id
                try:
                    ret = session.query(SFUser).filter_by(**filtering).one()
                    return row2dict(ret)
                except MultipleResultsFound:
                    # TODO(mhu) find a better Error
                    raise KeyError('search returned more than one result')
                except NoResultFound:
                    return {}
            else:
                # all()
                all = [row2dict(ret) for ret in session.query(SFUser)]
                return all

    def update(self, id, username=None, email=None,
               fullname=None, cauth_id=None, idp_sync=None):
        with session_scope() as session:
            try:
                ret = session.query(SFUser).filter_by(id=id).one()
                if username:
                    ret.username = username
                if email:
                    ret.email = email
                if fullname:
                    ret.fullname = fullname
                if cauth_id:
                    ret.cauth_id = cauth_id
                if idp_sync is not None:
                    ret.idp_sync = idp_sync
                session.commit()
            except MultipleResultsFound:
                msg = 'SF_USERS table has multiple row with the same id!'
                logger.error(msg)
                raise KeyError(msg)
            except NoResultFound:
                logger.warn("Could not update user %s: not found" % id)
                return

    def create(self, username, email,
               fullname, cauth_id=None):
        with session_scope() as session:
            if username and email and fullname:
                # assign a dummy value in case we lack the information
                # as is likely to happen when migrating from a previous version
                # TODO(mhu) remove these for version n+2
                cid = cauth_id or -1
                user = SFUser(username=username,
                              email=email,
                              fullname=fullname,
                              cauth_id=cid)
                session.add(user)
                session.commit()
                return user.id
            else:
                msg = "Missing info required for user creation: %s|%s|%s"
                raise KeyError(msg % (username, email, fullname))

    def delete(self, id=None, username=None, email=None,
               fullname=None, cauth_id=None):
        with session_scope() as session:
            filtering = {}
            if id:
                filtering['id'] = id
            if username:
                filtering['username'] = username
            if email:
                filtering['email'] = email
            if fullname:
                filtering['fullname'] = fullname
            if cauth_id:
                filtering['cauth_id'] = cauth_id
            try:
                ret = session.query(SFUser).filter_by(**filtering).one()
                session.delete(ret)
                session.commit()
                return True
            except MultipleResultsFound:
                # TODO(mhu) find a better Error
                raise KeyError('Too many candidates for deletion')
            except NoResultFound:
                return False


class NodepoolImageUpdate(Base):
    __tablename__ = 'NODEPOOL_IMAGE_UPDATES'
    id = Column(Integer(), primary_key=True)
    status = Column(String(255), default="IN_PROGRESS")
    provider = Column(String(1024), nullable=False)
    image = Column(String(1024), nullable=False)
    exit_code = Column(Integer(), default=-1)
    stderr = Column(UnicodeText(), default="")
    output = Column(UnicodeText(4294967295), default="")


class ImageUpdatesCRUD():
    def create(self, provider, image):
        with session_scope() as session:
            if provider and image:
                img_update = NodepoolImageUpdate(
                              provider=provider,
                              image=image)
                session.add(img_update)
                session.commit()
                return img_update.id
            else:
                msg = "Missing info required for image update: %s|%s"
                raise KeyError(msg % (provider, image))

    def update(self, id, status=None, exit_code=None,
               output=None, stderr=None):
        with session_scope() as session:
            try:
                u = session.query(NodepoolImageUpdate).filter_by(id=id).one()
                if status:
                    u.status = status
                if exit_code:
                    u.exit_code = int(exit_code)
                if output:
                    u.output = output
                if stderr:
                    u.stderr = stderr
                session.commit()
            except NoResultFound:
                logger.warn("Could not update image-update %s: not found" % id)
                return

    def get(self, id):
        with session_scope() as session:
            # TODO(mhu) Lookup by images, providers, statuses if needed?
            try:
                u = session.query(NodepoolImageUpdate).filter_by(id=id).one()
                return row2dict(u)
            except NoResultFound:
                return {}


def init_model():
    c = dict(conf.sqlalchemy)
    url = c.pop('url')
    if url.startswith('mysql://'):
        url = url.replace('mysql://', 'mysql+pymysql://')
    if url.startswith('mysql') and not url.endswith('?charset=utf8'):
        url += '?charset=utf8'
    globals()['engine'] = create_engine(url, pool_recycle=600, **c)
    if url.startswith('mysql'):
        event.listen(engine, 'checkout', checkout_listener)
    Base.metadata.create_all(engine)


def start_session():
    Base.metadata.bind = engine
    dbsession = sessionmaker(bind=engine)
    session = dbsession()
    return session


@contextmanager
def session_scope():
    session = start_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def add_user(user):
    """ Add a user in the database
        return Boolean
    """
    try:
        with session_scope() as session:
            u = User(**user)
            session.add(u)
            return True, None
    except exc.IntegrityError as e:
        return False, str(e)


def get_user(username):
    """ Fetch a user by its username
        return user dict or False if not found
    """
    try:
        with session_scope() as session:
            ret = session.query(User).filter_by(username=username).one()
            return row2dict(ret)
    except NoResultFound:
        return False


def delete_user(username):
    """ Delete a user by its username
        return True if deleted or False if not found
    """
    with session_scope() as session:
        ret = session.query(User).filter_by(username=username).delete()
        return bool(ret)


def update_user(username, infos):
    """ Update a user by its username
        arg infos: Dict
        return True if deleted or False if not found
    """
    with session_scope() as session:
        user = session.query(User)
        ret = user.filter_by(username=username).update(infos)
        return bool(ret)
