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

from managesf import model
from basicauth import decode, DecodeError
from passlib.hash import pbkdf2_sha256


log = logging.getLogger(__name__)


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
    reason = ''
    if not model.get_user(username):
        log.info(u"Adding user %s" % username)
        infos['username'] = username
        verify_input(infos)
        hash_password(infos)
        ret, reason = model.add_user(infos)
        if ret:
            del infos['hashed_password']
            ret = infos
    else:
        log.info("Updating user %s" % username)
        verify_input(infos)
        hash_password(infos)
        ret = model.update_user(username, infos)
    if not ret:
        raise BadUserInfos(
            'Bad infos input%s.' % (': %s' % reason))
    else:
        return ret


def delete_user(username):
    log.info(u"Deleting user %s" % username)
    ret = model.delete_user(username)
    if not ret:
        raise UserNotFound("%s not found" % username)
    return ret


def get_user(username):
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
        log.warning(u"User not found %s" % username)
        raise UserNotFound("%s not found" % username)
    if pbkdf2_sha256.verify(password, ret['hashed_password']):
        del ret['hashed_password']
        return ret
    else:
        log.warning(u"Invalid password for user %s" % username)
        raise BindForbidden("Authentication failed")
