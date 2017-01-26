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

import re
import logging

from managesf.services.storyboard import SoftwareFactoryStoryboard

logger = logging.getLogger(__name__)

NAME_RE = "^[a-zA-Z0-9]+([_\-\./]?[a-zA-Z0-9]+)*$"
PROJECT_NAME_RE = re.compile(NAME_RE)
NAME_MIN_LEN = 5


class StoryboardOps(object):

    def __init__(self, conf, new={}):
        self.conf = conf
        self.new = new
        self.client = None

    def is_activated(self, **kwargs):
        if ("SFStoryboard" in self.conf.services and
                kwargs.get('issue-tracker') == "SFStoryboard"):
            return True
        return False

    def _set_client(self):
        if not self.client:
            stb = SoftwareFactoryStoryboard(self.conf)
            self.client = stb.get_client()

    def extra_validations(self, **kwargs):
        logs = []
        if len(kwargs['name']) < NAME_MIN_LEN:
            logs.append("Storyboard project name %s length is invalid"
                        " (Minimal len is %s)" % (
                            kwargs['name'], NAME_MIN_LEN))
        sources_repositories = kwargs['source-repositories']
        for name in sources_repositories:
            if len(name) < NAME_MIN_LEN:
                logs.append(
                    "Storyboard project name %s length is invalid"
                    " (Minimal len is %s)" % (name, NAME_MIN_LEN))
            if not PROJECT_NAME_RE.match(name):
                logs.append(
                    "Storyboard project name %s is invalid"
                    " (It should match the RE(%s))" % (name, NAME_RE))
        return logs

    def update_project(self, name, description):
        self._set_client()
        project = [p for p in self.client.projects.get_all(name=name)
                   if p.name == name]
        if project:
            project = project[0]
            self.client.projects.update(
                id=project.id, description=description)
        else:
            # Create the project
            self.client.projects.create(
                name=name, description=description)

    def delete_project(self, name):
        raise NotImplementedError('Not supported by Storyboard')

    def update_project_groups(self, **kwargs):
        name = kwargs['name']
        sources_repositories = kwargs['source-repositories']
        self._set_client()
        pg = [p for p in self.client.project_groups.get_all(name=name)
              if p.name == name]
        if not pg:
            # Create the project group
            pg = self.client.project_groups.create(
                name=name, title=name)
        else:
            pg = pg[0]
        included_ids = [
            p.id for p in
            self.client.project_groups.get(id=pg.id).projects.get_all()]
        wanted_included = []
        for sr_name in sources_repositories:
            sr = self.new['resources']['repos'][sr_name]
            self.update_project(name=sr_name,
                                description=sr['description'])
            project = [p for p in self.client.projects.get_all(name=sr_name)
                       if p.name == sr_name]
            if project:
                wanted_included.append(project[0].id)
        to_add = set(wanted_included) - set(included_ids)
        to_remove = set(included_ids) - set(wanted_included)
        for id in to_add:
            self.client.project_groups.update(id=pg.id).projects.put(id=id)
        for id in to_remove:
            self.client.project_groups.update(id=pg.id).projects.delete(id=id)

    def delete_project_groups(self, **kwargs):
        name = kwargs['name']
        self._set_client()
        pg = [p for p in self.client.project_groups.get_all(name=name)
              if p.name == name]
        pg = pg[0]
        included_ids = [
            p.id for p in
            self.client.project_groups.get(id=pg.id).projects.get_all()]
        for id in included_ids:
            self.client.project_groups.update(id=pg.id).projects.delete(id=id)
        self.client.project_groups.delete(id=pg.id)


if __name__ == '__main__':
    from pecan import configuration
    conf = configuration.conf_from_file('/etc/managesf/config.py')
    c = StoryboardOps(conf)
    c._set_client()
    # Warn there is a minimal name length for project name
    c.update_project('project1', 'the project p1')
