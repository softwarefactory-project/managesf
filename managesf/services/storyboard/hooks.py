#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat <licensing@enovance.com>
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
import re
from six.moves import urllib_parse

from managesf.services import base


logger = logging.getLogger(__name__)


gitweb_url_suffix = "/r/gitweb?p=%(project)s;a=commit;h=%(commit)s"
CREATED = """Fix proposed to branch: %(branch)s by %(submitter)s
Review: %(url)s %(title)s
"""
MERGED = """The following change on Gerrit has been merged to: %(branch)s

Review: %(url)s

Submitter: %(submitter)s

Commit message:

%(commit)s

gitweb: %(gitweb)s
"""

STORIES = re.compile(r"^[Ss]tory:\s+\#?(\d+)", re.VERBOSE | re.MULTILINE)
TASKS = re.compile(r"^[Tt]ask:\s+\#?(\d+)", re.VERBOSE | re.MULTILINE)

RELATED_STORIES = re.compile(r"^[Rr]elated[ -][Ss]tory:\s+\#?(\d+)",
                             re.VERBOSE | re.MULTILINE)
RELATED_TASKS = re.compile(r"^[Rr]elated[ -][Tt]ask:\s+\#?(\d+)",
                           re.VERBOSE | re.MULTILINE)


def generic_storyboard_hook(kwargs, task_status,
                            gitweb_url, template_message, client):
    gitweb = gitweb_url % {'project': kwargs.get('project') + '.git',
                           'commit': kwargs.get('commit')}
    submitter = kwargs.get('submitter')
    if not submitter:
        submitter = kwargs.get('uploader')
    if not submitter:
        submitter = kwargs.get('change_owner')

    commit = kwargs.get('commit_message', '')

    commit_lines = commit.split('\n')
    if len(commit_lines) >= 6:
        commit_title = commit_lines[5]
        commit_message = '\n'.join(map(lambda x: "    %s" % x,
                                       commit_lines[5:]))
    else:
        commit_title = ''
        commit_message = ''

    message = template_message % {'branch': kwargs.get('branch'),
                                  'url': kwargs.get('change_url'),
                                  'submitter': submitter,
                                  'commit': commit_message,
                                  'gitweb': gitweb,
                                  'title': commit_title}

    tasks = TASKS.findall(commit)
    if task_status == 'inprogress':
        related_tasks = RELATED_TASKS.findall(commit)
    else:
        # Don't update related task on change_merged
        related_tasks = []
    stories = STORIES.findall(commit) + RELATED_STORIES.findall(commit)

    errors = []

    for task in tasks + related_tasks:
        try:
            if client.tasks.get(task).status != task_status:
                client.tasks.update(id=task, status=task_status)
                logger.info("Updated task %s status to '%s'" % (task,
                                                                task_status))
        except Exception, e:
            errors.append(str(e))
    for story in stories:
        try:
            story = client.stories.get(story)
            commented = False
            for comment in story.comments.list():
                if comment.content == message:
                    commented = True
                    break
            if not commented:
                story.comments.create(content=message)
                logger.info("Commented on story %s '%s'" % (story.id,
                                                            story.title))
        except Exception, e:
            errors.append(str(e))
    if not tasks and not related_tasks and not stories:
        return "No issue found in the commit message, nothing to do."
    if errors:
        return ", ".join(errors)
    return "Success"


class StoryboardHooksManager(base.BaseHooksManager):

    def patchset_created(self, *args, **kwargs):
        """Set tickets impacted by the patch to 'In Progress'."""
        gitweb_url = urllib_parse.urljoin(self.plugin.conf['base_url'],
                                          gitweb_url_suffix)
        msg = generic_storyboard_hook(kwargs, "inprogress", gitweb_url,
                                      template_message=CREATED,
                                      client=self.plugin.get_client())
        logger.debug(u'[%s] %s: %s' % (self.plugin.service_name,
                                       'patchset_created',
                                       msg))
        return msg

    def change_merged(self, *args, **kwargs):
        """Set tickets impacted by the patch to 'Closed' if the patch
        resolves the issue."""
        gitweb_url = urllib_parse.urljoin(self.plugin.conf['base_url'],
                                          gitweb_url_suffix)
        msg = generic_storyboard_hook(kwargs, "merged", gitweb_url,
                                      template_message=MERGED,
                                      client=self.plugin.get_client())
        logger.debug('[%s] %s: %s' % (self.plugin.service_name,
                                      'patchset_created',
                                      msg))
        return msg
