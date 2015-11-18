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

from pecan import conf
import logging
from utils import RemoteUser
import time

logger = logging.getLogger(__name__)


class Backup(object):
    def __init__(self):
        path = conf.managesf['sshkey_priv_path']
        self.jru = RemoteUser('root', conf.jenkins['host'], path)
        self.msqlru = RemoteUser('root', conf.mysql['host'], path)
        self.mru = RemoteUser('root', conf.managesf['host'], path)

    def check_for_service(self, ru, service):
        attempt = 0
        # Wait up to 10 minutes for gerrit to restart
        while attempt <= 300:
            p = ru._ssh(service)
            logger.debug(" Return status is %s" % p.returncode)
            if p.returncode != 0:
                time.sleep(2)
                attempt += 1
            else:
                break

    def start(self):
        logger.debug("start backup of mysql")
        p = self.msqlru._ssh('/root/backup_mysql.sh')
        logger.info("-> Mysql backup ended with code: %d" % p.returncode)

        logger.debug("generate backup")
        self.mru._ssh(
            'tar --absolute-names -czPf ' +
            '/var/www/managesf/sf_backup.tar.gz /root/.bup /root/*db.sql.gz')
        self.mru._ssh('chmod 0400 /var/www/managesf/sf_backup.tar.gz')
        self.mru._ssh('chown apache:apache /var/www/managesf/sf_backup.tar.gz')

    def unpack(self):
        self.mru._ssh('tar -xzPf /var/www/managesf/sf_backup.tar.gz')

    def restore(self):
        p = self.msqlru._ssh('/root/restore_mysql.sh')
        logger.info("Mysql restoration ended with code: %d" % p.returncode)


def backup_start():
    bkp = Backup()
    bkp.start()


def backup_unpack():
    bkp = Backup()
    bkp.unpack()


def backup_restore():
    bkp = Backup()
    bkp.restore()
