..
  Please note: if you change this file you need to rebuild the manpage using the
  following command and commit the manpage file too:

  sphinx-build -b man docs/source/ docs/man/
  git add docs/man/sfmanager.1
  git commit

.. toctree::

sfmanager
=========

This documentation describes the shell utility **sfmanager**, which is a CLI for
the managesf REST API interface in Software Factory. It can be used to
administrate Software Factory, for example to manage projects and users.

Introduction
------------

Global options
''''''''''''''

By default all actions require authentication as well as some information about
the remote servers.

\--url <http://sfgateway.dom>
    URL of the managesf instance

\--auth user:password
    Username and password to use when accessing the managesf interface.
    This option is only valid if it is a local user within Software Factory

There are a few optional arguments as well:

\--insecure
    Disable SSL certificate verification. Enabled by default

\--debug
    Enable debug messages in console. Disabled by default


Example usage
'''''''''''''

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           project create

Help
''''

Help is always available using the argument '-h':

.. code-block:: bash

 sfmanager project -h
 usage: sfmanager project [-h]
                          {delete_user,add_user,list_active_users,create,delete}
                          ...

.. _managesf_create_project:

Project management
------------------

Create new project
''''''''''''''''''

SF exposes ways to create and initialize projects in Redmine and Gerrit
simultaneously. Initializing a project involves setting up the ACL and
initializing the source repository.

Any user that can authenticate against SF will be able to create a project.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           project create --name <project-name>

There are a few more options available in case you want to customize the
project.

\--description [project-description], -d [project-description]
    An optional description of the project.

\--upstream [GIT link], -u [GIT link]
    Uses the given repository to initalize the project, for example to reuse an existing Github repository

\--upstream-ssh-key upstream-ssh-key
    SSH key for upstream repository if authentication is required

\--core-group [core-group-members], -c [core-group-members]
    A list of comma-separated member ids that are setup as core reviewers. Core
    reviewers can approve or block patches; by default a review from at least
    one core is required to merge a patch.

\--ptl-group [ptl-group-members], -p [ptl-group-members]
    A list of comma-separated member ids that are setup as PTLs (Project
    Technical Lead). The members can give core permissions to other users.

\--dev-group [dev-group-members], -e [dev-group-members]
    A list of comma-separated member ids that are setup as developers of this
    project. Only required if a project is marked private.

\--private
    Mark project as private. In that case only members of the dev, core or ptl
    group are allowed to access the project.

Delete Project
''''''''''''''

SF exposes ways to delete projects and the groups associated with the project in
Redmine and Gerrit simultaneously.

For any project, only the PTLs shall have the permission to delete it.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           project delete --name <project-name>


Group management
----------------

Default groups
''''''''''''''

When a project is created a few default project groups are created. To modify
these groups a user needs to be at least in the same group of users.

projectname-ptl
    Group of PTLs. Members can add other users to all groups.
projectname-core
    Group of core reviewers. Members can add other users to the groups
    projectname-core and projectname-dev
projectname-dev
    Group of developers, required when project is private. Members can not add
    any other user to any group.

List project users
''''''''''''''''''

Currently only lists all known users. This command is useful for the "add"
subcommand of the membership command or for `--ptl-group`, `--core-group`,
`--dev-group` of the project create options.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership list


Add user to project groups
''''''''''''''''''''''''''

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership add --user user1@tests.dom --project p1 \
           --groups ptl-group core-group



Remove user from project groups
'''''''''''''''''''''''''''''''

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership remove --user user1@tests.dom --project p1 \
           --group ptl-group

If the request does not provide a specific group to delete the user from, SF
will remove the user from all groups associated to a project.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership remove --user user1@tests.dom --project p1


User management
---------------

These commands manage the local users, that are not using external
authentication systems like Github.


Add user
''''''''

Creates a new local user and registers the user in Gerrit and Redmine

\--username [username], -u [username]
    A unique username/login

\--password [password], -p [password]
    The user password, can be provided interactively if this option is empty

\--email [email], -e [email]
    The user email

\--fullname [John Doe], -f [John Doe]
    The user's full name, defaults to username

\--ssh-key [/path/to/pub_key], -s [/path/to/pub_key]
    The user's ssh public key file

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user create --username jdoe --password secret --fullname "User Tester" \
                --email jane@doe.org

Update user
'''''''''''

Update an existing local user. A user can update it's own details, and admins
can also update other user details. Takes the same arguments as user create.
The options `--fullname` and `--ssh-key` (if updated) won't be taken in account
inside SF services. Only the password can be updated.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user update --username jdoe --password unguessable


Delete user
'''''''''''

Disable the user's account. That does not prevent the user from contributing, it
only prevents the user from login in to Software Factory.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user delete --username jdoe


Remote replication mangement
----------------------------

Gerrit can be configured to push merged changes to another git repository.  This
can be used to mirror changes on a public available repository, for example on
Github or to keep another copy as a backup.

Details about the configuration within Gerrit itself can be found online:
https://gerrit.googlesource.com/gerrit/+/stable-2.4/Documentation/config-replication.txt


Add a replication config setting
''''''''''''''''''''''''''''''''

The minimum requirement is to set a remote git url. Every replication target
requires it's own section within Gerrits configuration file, thus you need to
set a sectionname for each replication target.

There are a few settings you can use in a replication configuration section:

url 'gerrit@$hostname:/path/git/${name}.git'
    Set the remote url. The variable "${name}" will be replaced by the
    projectname and can be used if multiple projects will be replicated by this
    configuration.
    Can be specified multiple times to replicate to several hosts. In this case
    the option "threads" might be used to configure Gerrit to replicate in
    parallel.

projects project1,project2
    Limits the replication to the previously defined url to projects "project1,
    project2". Note that there is no space between the project names.

push "+refs/heads/*:refs/heads/*"
    refspec denoting what should be replicated. Can be specified multiple times.

Further valid setting names are: **receivepack**, **uploadpack**, **timeout**, **replicationDelay**, **threads**.

Example:

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure add --section sectionname \
           url 'gerrit@$hostname:/path/git/${name}.git'

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure add --section sectionname projects projectname


Trigger replication manually
''''''''''''''''''''''''''''

Replication is triggered automatically by default, though Gerrit delays this a
little bit (15 seconds by default) to batch multiple commits into a single push operation.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication trigger --project config


List existing replication configs and settings
''''''''''''''''''''''''''''''''''''''''''''''

Existing replication configuration can be shown using the two commands **list**
and **get-all**. The first command lists all configured replications that the user
has access to, the second command lists only settings from a specific
configuration section and can be filtered to a single setting too.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure list

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication get-all --section sectionname

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication get-all --section sectionname url


Delete replication config
'''''''''''''''''''''''''

Deleting a replication target only stops replicating data to this target. It
does not remove data on the remote side.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication remove-section sectionname

Modify existing settings
''''''''''''''''''''''''

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure replace-all --section sectionname projects project1,project3


Using SSH keys to authenticate replication
''''''''''''''''''''''''''''''''''''''''''

Gerrit reads ~/.ssh/config on startup and uses defined configuration settings
when connecting to remote replication targets. Authentication is done using SSH
keys, thus they need to be defined first.
Some replication sites don't allow to re-use a single SSH key for authentication
with different repositories, for example Github. In that case you can define
multiple different SSH keys, and instead of directly using a hostname you only
define an alias for the "Host" value. The SSH keys have to be copied to the
Gerrit node in advance.

An example setting for an alias host might look like this:

.. code-block:: none

 Host alias_gh_firstrepo
    Hostname github.com
    IdentityFile ~/.ssh/gh_firstrepo
    PreferredAuthentications publickey

 Host alias_gh_secondrepo
    Hostname github.com
    IdentityFile ~/.ssh/gh_secondrepo
    PreferredAuthentications publickey

The corresponding Gerrit replication can be created using the following URLs:

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure add --section firstrepo url 'git@alias_gh_firstrepo:accountname/${name}.git'

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure add --section firstrepo projects projectname1

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure add --section secondrepo url 'git@alias_gh_secondrepo:accountname/${name}.git'

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           replication configure add --section secondrepo projects projectname2


You can use sfmanager also to add or remove SSH keys to Gerrit. For example.

.. code-block:: bash

 ssh-keygen -N "" -f private_ssh.key

 sfmanager --url <http://sfgateway.dom> \
     --auth user1:userpass \
     gerrit_ssh_config add --alias aliasname --key private_ssh.key --hostname sample.github.com

 sfmanager --url <http://sfgateway.dom> \
     --auth user1:userpass \
     gerrit_ssh_config delete --alias sample


A complete example using GitHub
'''''''''''''''''''''''''''''''
The following commands show a complete example how to create a simple new
project and add a SSH-key based authentication for replication to GitHub. Create
a new public/private SSH key and add the content of the file private_ssh.key.pub
to your GitHub repository (in settings / Deploy keys; don't forget to enable
write access)

.. code-block:: bash

 ssh-keygen -N "" -f private_ssh.key

Create a new project if required

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> \
     --auth user1:userpass \
     project create --name testrepo

Now add the replication config and SSH keys

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> \
     --auth user1:userpass \
     replication configure add --section testrepo url 'git@alias_gh_firstrepo:username/${name}.git'

 sfmanager --url <http://sfgateway.dom> \
     --auth user1:userpass \
     replication configure add --section testrepo projects testrepo

 sfmanager --url <http://sfgateway.dom> \
     --auth user1:userpass \
     gerrit_ssh_config add --alias alias_gh_firstrepo --key private_ssh.key --hostname github.com

Finally trigger the initial replication

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> \
     --auth user1:userpass \
     replication trigger

Done! After a few minutes your commits should appear on the GitHub repository.


Backup and restore
------------------

Backups include data from Gerrit, Jenkins and Mysql. Because Mysql is used as
the default backend in Redmine, Paste and Etherpad all of this data is also
included in the backup file.

Create a new backup
'''''''''''''''''''

SF exposes ways to perform and retrieve a backup of all the user data store in
your SF installation. This backup can be used in case of disaster to quickly
recover user data on the same or another SF installation (of the same version).

Only the SF administrator can perform and retrieve a backup.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           system backup_start

Once the server generated the tar file of the backup you can then download it with
the following command

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           system backup_get

A file called "sf_backup.tar.gz" will be created in the local directory.


Restore a backup
''''''''''''''''

SF exposes ways to restore a backup of all the user data store in your
SF installation. This backup can be used in case of disaster to quickly
recover user data on the same or other SF installation (in the same version).

Only the SF administrator can restore a backup.

SF allows you to restore a backup in one of the following way.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           system restore --filename sf_backup.tar.gz


Provide a private ssh key to the Gerrit replication plugin
----------------------------------------------------------

To request a random password to access the Gerrit API for the current user. This
is useful for using tools like  `gertty <https://github.com/stackforge/gertty>`_ .

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                gerrit_api_htpasswd generate_password

and to deactivates the password from Gerrit.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                gerrit_api_htpasswd delete_password


Configuring Gerrit ssh key
--------------------------

To provide private ssh keys to Gerrit's replication plugin.
`A complete example using GitHub replication in Software Factory </docs/deploy.html#setup-replication-to-github>`_

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                gerrit_ssh_config add --hostname git_hub.com/user/prj1 \
                --alias prj1 --keyfile ssh-public-key-path

and to remove the ssh key.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                gerrit_ssh_config delete --alias prj1


Initiate the test pipeline
--------------------------

Once you create a project, you can initiate the project's tests into Software
Factory's pipeline. The result is a entry into the Software Factory's
configuration repository that will require review. It will also create
placeholder scripts in your project. To skip the generation of the placeholder
just add `--no-scripts`.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                tests init --project prj1
