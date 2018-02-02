#!/usr/bin/python
#
# Copyright (c) 2018 Red Hat, Inc.
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


import os
import time
import json
import logging
from pecan import configuration  # noqa
from managesf.model import init_model
from managesf.model import get_resources_task
from managesf.model import update_resources_task
from managesf.model import get_resources_tasks_pending
from managesf.model.yamlbkd.engine import SFResourceBackendEngine


logger = logging.getLogger('managesf.resources_apply_service')


def run_task(conf, apply_task):
    eng = SFResourceBackendEngine(
        os.path.join(conf.resources['workdir'], 'apply'),
        conf.resources['subdir'])
    if apply_task['type'] == 'apply':
        status, logs = eng.apply(
            apply_task['prev_uri'], apply_task['prev'],
            apply_task['new_uri'], apply_task['new'])
    elif apply_task['type'] == 'direct_apply':
        status, logs = eng.direct_apply(
            apply_task['prev'], apply_task['new'])
    else:
        # We should never be there.
        status = True
        logs = ""
    return status, logs


def run(conf):
    while True:
        pendings = get_resources_tasks_pending()
        if pendings:
            tids = [pending['id'] for pending in pendings]
            # Select older id
            selected_id = min(tids)
            logger.info("Got pending task %s" % selected_id)
            # Get the selected task
            ra = get_resources_task(selected_id)
            # Run the apply task
            update_resources_task(
                selected_id, {'status': 'PROGRESS'})
            status, logs = run_task(conf, ra)
            # Report status to the database
            if status:
                txt_status = "DONE"
            else:
                txt_status = "ERROR"
            ra_status = {
                "status": txt_status,
                "output": json.dumps(logs)}
            logger.info("Finished task %s." % selected_id)
            logger.info("Updating task %s." % selected_id)
            update_resources_task(selected_id, ra_status)
        time.sleep(1)


def main():
    confpath = configuration.get_conf_path_from_env()
    conf = configuration.conf_from_file(confpath)
    configuration.set_config(conf.to_dict())
    conf.logging.version = 1
    logging.config.dictConfig(conf.logging.to_dict())
    init_model()
    logger.info("Start the resources apply engine")
    run(conf)
