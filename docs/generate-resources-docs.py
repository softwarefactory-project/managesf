#!/usr/bin/env python

from unittest.mock import patch, MagicMock

m_mock = MagicMock()

# Patch all useless module imports for generating the doc
modules = {'managesf.services.gerrit': m_mock,
           'git': m_mock,
           'yaml': m_mock,
           'deepdiff': m_mock,
           'requests': m_mock,
           'requests.exceptions': m_mock,
           'git.config': m_mock,
           'pecan': m_mock,
           'pynotedb': m_mock,
           'sqlalchemy': m_mock,
           'sqlalchemy.orm': m_mock,
           'sqlalchemy.ext': m_mock,
           'sqlalchemy.orm.exc': m_mock,
           'sqlalchemy.ext.declarative': m_mock,
           'storyboardclient': m_mock,
           'storyboardclient._apiclient': m_mock,
           'storyboardclient._apiclient.exceptions': m_mock,
           'storyboardclient.v1': m_mock,
           'storyboardclient.v1.client': m_mock}

m_patcher = patch.dict('sys.modules', modules)
m_patcher.start()

from managesf.model.yamlbkd.resources.gitrepository import GitRepository
from managesf.model.yamlbkd.resources.project import Project
from managesf.model.yamlbkd.resources.gitacls import ACL
from managesf.model.yamlbkd.resources.group import Group

from managesf.model.yamlbkd.engine import MAPPING


def render_resource(cls):
    print()
    print(cls.MODEL_TYPE)
    print("^"*len(cls.MODEL_TYPE))
    print()
    print(cls.DESCRIPTION)
    print()
    print("Below are the list of keys available for this resource.")
    print()
    for key, details in cls.MODEL.items():
        if key == "name":
            key = "name (Overwritten by the resource ID)"
            print()
            print(key)
            print('"'*len(key))
            print("* **Description:** %s" % details[5])
            print("* **Authorized value:** RE(%s)" % details[1])
            print("* **Mandatory key:** %s" % details[2])
        else:
            print()
            print(key)
            print('"'*len(key))
            print("* **Description:** %s" % details[5])
            print("* **Type:** %s" % str(details[0]))
            print("* **Authorized value:** RE(%s)" % str(details[1]))
            print("* **Mandatory key:** %s" % details[2])
            print("* **Mutable key:** %s" % details[4])
            if not details[2]:
                default = details[3]
                if isinstance(default, str) and not len(default):
                    default = "\"\""
                print("* **Default value:** %s" % default)

if __name__ == '__main__':
    print(".. _config-resources-model:")
    print()
    print("Available resources models")
    print("==========================")
    print()
    print("Containers / Resources mapping")
    print("------------------------------")
    for container, cls in MAPPING.items():
        print("* Model type: **%s** can only be "
              "defined in container: **%s**" % (
                  cls.MODEL_TYPE, container))
    print()
    print("Resources")
    print("---------")
    print()
    print("Note that the key **name** for every resource type"
          " is not mandatory. A resource is referenced via"
          " its resource's ID that will automatically become the resource"
          " **name** value. The resource's ID must validate the **name**"
          " value constraint of the related resource type. If you still"
          " want to specify the name then please make sure to have"
          " the resource ID equals to the resource name.")
    print()
    for cls in (Project, ACL, GitRepository, Group):
        render_resource(cls)
