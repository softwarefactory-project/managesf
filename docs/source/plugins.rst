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

If you are writing your own plugin library, you need to declare your plugins in
the entry points section of your library's setup.py, under the namespace
"managesf.v2.<ENDPOINT>" where <ENDPOINT> is the API endpoint you want to implement.

The expected interface varies from endpoint to endpoint and can usually be found
in managesf/api/v2/<ENDPOINT>.
