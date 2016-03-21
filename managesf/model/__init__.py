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

from pecan import conf  # noqa
from sqlalchemy import create_engine, Column, String, exc, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()
engine = None


def row2dict(row):
    ret = {}
    for column in row.__table__.columns:
        ret[column.name] = str(getattr(row, column.name))
    return ret


class User(Base):
    __tablename__ = 'users'
    username = Column(String(255), primary_key=True)
    fullname = Column(String(255), nullable=False)
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


def init_model():
    c = dict(conf.sqlalchemy)
    url = c.pop('url')
    globals()['engine'] = create_engine(url, pool_recycle=600, **c)
    if url.startswith('mysql'):
        event.listen(engine, 'checkout', checkout_listener)
    Base.metadata.create_all(engine)


def start_session():
    Base.metadata.bind = engine
    dbsession = sessionmaker(bind=engine)
    session = dbsession()
    return session


def add_user(user):
    """ Add a user in the database
        return Boolean
    """
    session = start_session()
    u = User(**user)
    session.add(u)
    try:
        session.commit()
        return True, None
    except exc.IntegrityError as e:
        return False, e.message


def get_user(username):
    """ Fetch a user by its username
        return user dict or False if not found
    """
    session = start_session()
    try:
        ret = session.query(User).filter(User.username == username).one()
    except NoResultFound:
        return False
    return row2dict(ret)


def delete_user(username):
    """ Delete a user by its username
        return True if deleted or False if not found
    """
    session = start_session()
    ret = session.query(User).filter(User.username == username).delete()
    session.commit()
    return bool(ret)


def update_user(username, infos):
    """ Update a user by its username
        arg infos: Dict
        return True if deleted or False if not found
    """
    session = start_session()
    ret = session.query(User).filter(User.username == username).update(infos)
    session.commit()
    return bool(ret)
