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

from pecan import conf
from pecan import request

from managesf import model
from basicauth import decode, DecodeError
from passlib.hash import pbkdf2_sha256


logger = logging.getLogger(__name__)


class AddUserForbidden(Exception):
    pass


class DeleteUserForbidden(Exception):
    pass


class UpdateUserForbidden(Exception):
    pass


class GetUserForbidden(Exception):
    pass


class UserNotFound(Exception):
    pass


class BadUserInfos(Exception):
    pass


class BindForbidden(Exception):
    pass


class InvalidInfosInput(Exception):
    pass


AUTHORIZED_KEYS = ('username',
                   'password',
                   'sshkey',
                   'email',
                   'fullname')


def verify_input(infos):
    for key in infos.keys():
        if key not in AUTHORIZED_KEYS:
            raise InvalidInfosInput("%s is not a valid key" % key)


def hash_password(infos):
    password = infos.get('password', None)
    if password is None:
        return
    del infos['password']
    hash = pbkdf2_sha256.encrypt(password,
                                 rounds=200,
                                 salt_size=16)
    infos['hashed_password'] = hash


def update_user(username, infos):
    if not model.get_user(username):
        if request.remote_user != conf.admin['name']:
            raise AddUserForbidden('Only %s can create a new user' %
                                   conf.admin['name'])
        if username == conf.admin['name']:
            raise AddUserForbidden('This user is reserved')
        infos['username'] = username
        verify_input(infos)
        hash_password(infos)
        ret = model.add_user(infos)
        if ret:
            del infos['hashed_password']
            ret = infos
    else:
        if request.remote_user != conf.admin['name'] and \
                request.remote_user != username:
            raise UpdateUserForbidden(
                '%s is trying to update %s. This is forbidden' %
                (request.remote_user, username))
        verify_input(infos)
        hash_password(infos)
        ret = model.update_user(username, infos)
    if not ret:
        raise BadUserInfos(
            'Something goes wrong with infos input. Not updated.')
    else:
        return ret


def delete_user(username):
    if request.remote_user != conf.admin['name']:
        raise DeleteUserForbidden("Only %s can delete an user" %
                                  conf.admin['name'])
    ret = model.delete_user(username)
    if not ret:
        raise UserNotFound("%s not found" % username)
    return ret


def get_user(username):
    if request.remote_user != conf.admin['name'] and \
            request.remote_user != username:
        raise GetUserForbidden("%s not allowed to fetch %s" %
                               (request.remote_user, username))
    infos = model.get_user(username)
    if not infos:
        raise UserNotFound("%s not found" % username)
    del infos['hashed_password']
    return infos


def bind_user(authorization):
    try:
        username, password = decode(authorization)
    except DecodeError:
        raise BindForbidden("Wrong authorization header")
    ret = model.get_user(username)
    if not ret:
        raise UserNotFound("%s not found" % username)
    if pbkdf2_sha256.verify(password, ret['hashed_password']):
        return True
    else:
        raise BindForbidden("Authentication failed")
