.. toctree::

Contributing
============

Pre-requisites
--------------

* Connect to https://softwarefactory-project.io/ to create an account. Software Factory
  supports authentication with OAuth providers like Github and Google.
* Register your public SSH key on your account (see Software Factory's documentation for more details)
* Install git-review on your development environment:

.. code-block:: bash

  sudo yum install git-review

Checking out the code
---------------------

.. code-block:: bash

  git clone ssh://$USER@softwarefactory-project.io:29418/software-factory/managesf.git
  git-review -s # will initialize the gerrit remote for review

where **$USER** is your user name on Software Factory.

Testing locally
---------------

Before submitting anything, make sure your patch passes the existing test suite
(PEP8, python 2.7):

.. code-block:: bash

  tox --recreate

Submitting a change
-------------------

.. code-block:: bash

  git checkout -b"my-branch"
  # Hack the code, create a commit on top of HEAD ! and ...
  git review # Submit your proposal on softwarefactory-project.io

Your patch will be listed on the reviews pages at https://softwarefactory-project.io/r/ .
Automatic tests are run against it and the CI will
report results on your patch's Gerrit page. You can
also check https://softwarefactory-project.io/zuul/ to follow the test process.
