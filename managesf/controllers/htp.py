#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

import random
import string
import htpasswd
import logging


logger = logging.getLogger(__name__)


class Htpasswd(object):
    def __init__(self, configuration):
        self.filename = None
        if getattr(configuration, "htpasswd", None):
            self.filename = configuration.htpasswd.get('filename')
            # Ensure file exists
            open(self.filename, "a").close()

    def user_has_api_password(self, user):
        try:
            with htpasswd.Basic(self.filename) as userdb:
                return user in userdb.users
        except IOError as e:
            logger.debug('Could not check htpasswd: %s' % e.message)
            raise e

    def delete(self, user):
        try:
            with htpasswd.Basic(self.filename) as userdb:
                userdb.pop(user)
        except htpasswd.basic.UserNotExists:
            # we don't care
            pass
        except IOError as e:
            logger.debug('Could not update htpasswd: %s' % e.message)
            raise e

    def set_api_password(self, user):
        password = ''.join(
            random.SystemRandom().choice(string.letters + string.digits)
            for _ in range(12))
        try:
            with htpasswd.Basic(self.filename) as userdb:
                try:
                    userdb.add(user, password)
                except htpasswd.basic.UserExists:
                    pass
                userdb.change_password(user, password)
                logger.debug('Updated htpasswd entry for user %s' % user)
        except IOError as e:
            logger.debug('Could not update htpasswd: %s' % e.message)
            raise e
        return password
