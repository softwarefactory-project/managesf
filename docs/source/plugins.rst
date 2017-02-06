.. toctree::

Service Plugins 
===============

The managesf server uses a plugin architecture to manage services. It means that
services can be added and configured into Software Factory quite easily.

Configuring services
--------------------

Services that will be provided in Software Factory through managesf must be declared
in the configuration file, in the "services" section, like so:

.. code-block:: none

  services = [
    'SFGerrit',
  ]

Each service has a dedicated configuration section. See below for more details,
but keep in mind that for services shipped with Software Factory, the configuration
is managed automatically when installing Software Factory's image and shouldn't
be modified.

Available services
------------------

SFGerrit
.........

Gerrit code review service packaged within Software Factory by default. Authentication
is managed by cauth.

*configuration section:* gerrit

=============================  =================================================
  Option                          Description
=============================  =================================================
  user                            the gerrit user
  host                            the gerrit host
  url                             the gateway URL
  top_domain                      the FQDN for the Software Factory deployment
  ssh_port                        the ssh port Gerrit listens on
  sshkey_priv_path                the path to Gerrit's private ssh key
  replication_config_path         the path to the replication configuration
=============================  =================================================


Writing a service plugin
------------------------

If you are writing your own plugin library, you need to declare your plugin in
the entry points section of your library's setup.py, under the namespace
"managesf.service".

The new plugin needs to inherit from one of the ServicePlugin classes defined in
managesf.services.base. Each class defines some specific managers to deal with
common actions in a "CRUD" way:

BaseServicePlugin
.................

  - project: project management
  - user: user management like creating or removing the user from the service's
    user backend
  - membership: management of the relationships between roles and users within a
    project
  - role: role management
  - backup: backup and restore operations

BaseIssueTrackerServicePlugin
.............................

Same as BaseServicePlugin, but defines also the method *get_open_issues*

BaseRepositoryServicePlugin
...........................

Same as BaseServicePlugin, plus

  - replication: replication operations management
  - repository: repository management

BaseCodeReviewServicePlugin
...........................

Same as BaseRepositoryServicePlugin, plus

  - review: reviews-related operations


The following calls should at least be implemented:

  - serviceplugin.backup.backup : called to backup data from the service
  - serviceplugin.backup.restore : called to restore data
  - service.membership.create/delete : called to add/remove a user's role in a project
  - service.project.create/delete : called to create/delete a project on Software Factory
