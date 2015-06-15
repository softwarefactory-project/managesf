# managesf

This is a REST-based utility to manage projects, users and other tasks in
SoftwareFactory(http://softwarefactory.enovance.com).
It consists of two parts: a server with a REST API interface and a command line
interface (CLI).

## Documentation

More information is included in the documentation(docs/intro.rst).

## Installation

### CLI sfmanager

Run the following commands if you only want to install the commandline tool:

 pip install -r requirements.txt
 python setup.py

### REST API server

Update config.py and execute the following commands if you want to run managesf in a development setup::

 virtualenv venv
 . venv/bin/activate
 pip install -r requirements.txt
 pecan serve config.py

To run it in production please refer to the Pecan documentation:

* Refer to pecan [doc](http://pecan.readthedocs.org/en/latest/deployment.html#deployment)
