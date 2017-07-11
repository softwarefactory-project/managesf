.. toctree::

Installation
============

ManageSF is installed automatically when deploying Software Factory, or when
using the sf-ci testing environment. However, should you want to install manageSF
outside of these contexts, here are two ways of doing so.

Using a package
---------------

manageSF is packaged for the latest CentOS distribution, it is therefore
recommended to install manageSF this way.

Install the latest repository:

.. code-block:: bash

   sudo yum install https://softwarefactory-project.io/repos/sf-release-2.6.rpm

Install the package:

.. code-block:: bash

   sudo yum install managesf

Installing from the source code
-------------------------------

Install the project requirements (as a privileged user, or within a virtualenv):

.. code-block:: bash

   pip install -r requirements.txt

Then install the library:

.. code-block:: bash

   python setup.py install
