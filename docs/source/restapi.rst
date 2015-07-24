.. toctree::

managesf REST API 
=================

This documentation describes the REST API interface of managesf that can be used
to develop backends for Software Factory. Please have a look at for a general
overview of the managesf tool as well as an introduction to the commandline tool
sfmanager.

Create Project
--------------

.. code-block:: none

 *PUT /project/{project-name}*

Additional data can be included in the request body. Valid options are:

===================  ==========  ===============================
     Field Name                      Description
===================  ==========  ===============================
description           Optional    A brief description about the
                                  project
core-group-members    Optional    The core developers for the
                                  projects separated by comma (,)
ptl-group-members     Optional    The project team leaders
                                  separated by comma (,)
dev-group-members     Optional    Developers for the project
                                  separated by comma (,)
upstream              Optional    Link to a git repo from which
                                  the current project's repo is
                                  initialized
upstream-ssh-key      Optional    SSH key for upstream repository
private               Optional    If set true, the project will
                                  be not be visible to users who
                                  are not in core-group,
                                  ptl-group and dev-group. If not
                                  true, the project would be
                                  visible to all the users
===================  ==========  ===============================

Request

.. code-block:: guess

 PUT /project/test-project
 Content-Type: application/json;charset=UTF-8
 Cookie: auth_pubtkt=..

 {
  "description": "This is a test project",
  "core-group-members": ["user1", "user2"],
  "ptl-group-members": ["user3"],
  "dev-group-members": ["user1", "user2", "user3"],
  "upstream": "http://github.com/redhat-cip/software-factory",
  "private": true
 }

Response

If successfully created, HTTP status code 200 is returned.

Delete Project
--------------

.. code-block:: none

 *DELETE /project/{project-name}*

Request

.. code-block:: guess

 DELETE /project/test-project
 Cookie: auth_pubtkt=..

Response

If successfully deleted, HTTP status code 200 is returned.
In case of errors, appropriate message will be sent with the response.

Add user to project groups
--------------------------

.. code-block:: none

 *PUT /project/membership/{project-name}/{user-name}*

A list of groups has to be included in the request body.

===================  ==========  ===============================
     Field Name                      Description
===================  ==========  ===============================
groups                Mandatory   A list of group to add user
===================  ==========  ===============================

Request

.. code-block:: guess

 PUT /project/membership/p1/user1
 Content-Type: application/json;charset=UTF-8
 Cookie: auth_pubtkt=..

 {
  "groups": ["p1-ptl", "p1-core"],
 }

Response

If successfully created, HTTP status code 200 is returned.

Remove user from project groups
-------------------------------

.. code-block:: none

 *DELETE /project/membership/{project-name}/{user-name}/{group-name}*
 *DELETE /project/membership/{project-name}/{user-name}*

A list of groups has to be included in the request body.

===================  ==========  ========================================
     Field Name                      Description
===================  ==========  ========================================
groups                Mandatory   A list of group to remove the user from
===================  ==========  ========================================

Request

.. code-block:: guess

 DELETE /project/membership/p1/user1/p1-core
 Cookie: auth_pubtkt=..

Response

If successfully created, HTTP status code 200 is returned.

Create SF backup
----------------

.. code-block:: none

 *GET /backup*

Request

.. code-block:: guess

 GET /backup
 Cookie: auth_pubtkt=..

Response

If successfully created, HTTP status code 200 is returned and
the body contains a gzip tar archive.

.. _CreateBackupCli:


Restore a backup
----------------

.. code-block:: none

 *POST /restore*

The backup archive must be sent in the request body as multipart form data.

Request

.. code-block:: guess

 POST /backup
 Content-Type: Content-Type: multipart/form-data; boundary=...
 Content-Length: ...
 Cookie: auth_pubtkt=..

Response

If successfully restored, HTTP status code 200 is returned. It may
take sometime for SF REST API to return an HTTP response.
