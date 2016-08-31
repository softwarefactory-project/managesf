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


import logging
from managesf import model


logger = logging.getLogger(__name__)


crud = model.SFUserCRUD()


class SFUserMapper:
    def set(self, sf_user_id, service, service_user_id):
        crud.set_service_mapping(sf_user_id, service, service_user_id)

    def get_service_mapping(self, service, sf_user_id):
        """Returns the service uid of user sf_user_id in service."""
        return crud.get_service_mapping(service, sf_user_id)

    def get_user_mapping(self, service, service_user_id):
        """Returns the managesf uid of user service_user_id in service."""
        return crud.get_user_mapping(service, service_user_id)

    def delete(self, sf_user_id, service=None, service_user_id=None):
        return crud.delete_service_mapping(sf_user_id,
                                           service,
                                           service_user_id)


class SFUserManager:
    mapping = SFUserMapper()

    def get(self, id=None, username=None, email=None,
            fullname=None, cauth_id=None):
        return crud.get(id=id, username=username, email=email,
                        fullname=fullname, cauth_id=cauth_id)

    def all(self):
        return self.get()

    def create(self, username, email,
               fullname, cauth_id=None):
        msg = u'Creating user: username=%s, email=%s, full name=%s'
        if cauth_id:
            msg += ', cauth_id=%s' % cauth_id
        logger.info(msg % (username, email, fullname))
        # cauth_id, if set, is our Authoritah (c)
        if cauth_id and cauth_id > 0:
            user = crud.get(cauth_id=cauth_id)
            if user:
                msg = u'Found user %s with cauth_id=%s, updating instead'
                logger.info(msg % (repr(user), cauth_id))
                crud.update(user['id'], username=username,
                            email=email, fullname=fullname)
                return user['id']
        # if not, check if we have a user with the same characteristics:
        user = crud.get(username=username, email=email, fullname=fullname)
        if user:
            if cauth_id and cauth_id != user.get('cauth_id'):
                msg = u'Found user %s, resetting cauth_id instead'
                msg += (' (this is normal if the SSO has been reset or the'
                        ' user has been recreated in the Identity Provider)')
                logger.info(msg % repr(user))
                self.reset_cauth_id(user['id'], cauth_id)
            else:
                msg = u'User %s already exists, doing nothing'
                logger.info(msg % repr(user))
            return user['id']
        return crud.create(username, email, fullname, cauth_id)

    def update(self, id, username=None, email=None, fullname=None,
               idp_sync=None):
        msg = u'Updating user info (id %s):' % id
        if username:
            msg += u' username=%s,' % username
        if email:
            msg += u' email=%s,' % email
        if fullname:
            msg += u' full name=%s' % fullname
        if idp_sync is not None:
            msg += u' idp_sync=%s' % idp_sync
        logger.info(msg)
        return crud.update(id, username=username,
                           email=email, fullname=fullname, idp_sync=idp_sync)

    def reset_cauth_id(self, id, cauth_id):
        msg = u'Updating user info (id %s): cauth_id=%s'
        logger.info(msg % (id, cauth_id))
        return crud.update(id, cauth_id=cauth_id)

    def delete(self, id=None, username=None,
               email=None, fullname=None, cauth_id=None):
        msg = u'Deleting user'
        if id:
            msg += u' (id %s):' % id
        else:
            msg += u':'
        if username:
            msg += u' username=%s,' % username
        if email:
            msg += u' email=%s,' % email
        if fullname:
            msg += u' full name=%s' % fullname
        if cauth_id:
            msg += u', cauth_id=%s' % cauth_id
        logger.info(msg)
        return crud.delete(id, username, email, fullname, cauth_id)
