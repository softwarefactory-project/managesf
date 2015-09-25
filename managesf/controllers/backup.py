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
from pecan import abort
import logging
from utils import RemoteUser
from gerrit import user_is_administrator
import time

logger = logging.getLogger(__name__)


class Backup(object):
    def __init__(self):
        if not user_is_administrator():
            abort(401)
        path = conf.managesf['sshkey_priv_path']
        self.gru = RemoteUser('root', conf.gerrit['host'], path)
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
        logger.debug(" start backup of Gerrit, jenkins and mysql")
        p = self.gru._ssh('/root/backup_gerrit.sh')
        logger.info("-> Gerrit backup: %d" % p.returncode)
        self.jru._ssh('/root/backup_jenkins.sh')
        logger.info("-> Jenkins backup: %d" % p.returncode)
        self.msqlru._ssh('/root/backup_mysql.sh')
        logger.info("-> Mysql backup: %d" % p.returncode)
        gerrit_service = 'wget --spider http://localhost:8000/r/'
        self.check_for_service(self.gru, gerrit_service)
        jenkins_service = 'wget --spider http://localhost:8082/jenkins/'
        self.check_for_service(self.jru, jenkins_service)

        logger.debug(" generate backup")
        self.mru._ssh(
            'tar --absolute-names -czPf ' +
            '/var/www/managesf/sf_backup.tar.gz /root/.bup /root/alldb.sql.gz')
        self.mru._ssh('chmod 0400 /var/www/managesf/sf_backup.tar.gz')
        self.mru._ssh('chown apache:apache /var/www/managesf/sf_backup.tar.gz')

    def restore(self):
        self.mru._ssh('tar -xzPf /var/www/managesf/sf_backup.tar.gz')
        self.msqlru._ssh('/root/restore_mysql.sh')
        self.gru._ssh('/root/restore_gerrit.sh')
        self.jru._ssh('/root/restore_jenkins.sh')
        gerrit_service = 'wget --spider http://localhost:8000/r/'
        self.check_for_service(self.gru, gerrit_service)
        jenkins_service = 'wget --spider http://localhost:8082/jenkins/'
        self.check_for_service(self.jru, jenkins_service)


def backup_start():
    bkp = Backup()
    bkp.start()


def backup_get():
    bkp = Backup()
    bkp.get()


def backup_restore():
    bkp = Backup()
    bkp.restore()
