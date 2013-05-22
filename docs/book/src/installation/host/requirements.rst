============
Requirements
============

Before proceeding on configuring Cuckoo, you'll need to install some required
softwares and libraries.

Installing Python libraries
===========================

Cuckoo host components are completely written in Python, therefore make sure to
have an appropriate version installed. For current release **Python 2.7** is preferred.

Install Python on Ubuntu::

    $ sudo apt-get install python

In order to properly function, Cuckoo requires SQLAlchemy to be installed.

Install with ``apt-get``::

    $ sudo apt-get install python-sqlalchemy

Install with ``pip``::

    $ sudo pip install sqlalchemy

There are other optional dependencies that are mostly used by modules and utilities.
The following libraries are not strictly required, but their installation is recommended:

    * `Dpkt`_ (Highly Recommended): for extracting relevant information from PCAP files.
    * `Jinja2`_ (Highly Recommended): for rendering the HTML reports and the web interface.
    * `Magic`_ (Optional): for identifying files' formats (otherwise use "file" command line utility)
    * `Pydeep`_ (Optional): for calculating ssdeep fuzzy hash of files.
    * `Pymongo`_ (Optional): for storing the results in a MongoDB database.
    * `Yara`_ and Yara Python (Optional): for matching Yara signatures (use release 1.7 or above or the svn version).
    * `Libvirt`_ (Optional): for using the KVM machine manager.
    * `Bottlepy`_ (Optional): for using the ``web.py`` and ``api.py`` utilities (use release 0.10 or above).
    * `Pefile`_ (Optional): used for static analysis of PE32 binaries.

Some of them are already packaged in Debian/Ubuntu and can be installed with the following command::

    $ sudo apt-get install python-dpkt python-jinja2 python-magic python-pymongo python-libvirt python-bottle python-pefile

Except for *python-magic* and *python-libvirt*, the others can be installed through ``pip`` too::

    $ sudo pip install dpkt jinja2 pymongo bottle pefile

*Yara* and *Pydeep* will have to be installed manually, so please refer to their websites.

If want to use KVM it's packaged too and you can install it with the following command::

    $ sudo apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils

.. _Magic: http://www.darwinsys.com/file/
.. _Dpkt: http://code.google.com/p/dpkt/
.. _Jinja2: http://jinja.pocoo.org/docs/
.. _Pydeep: https://github.com/kbandla/pydeep
.. _Pymongo: http://pypi.python.org/pypi/pymongo/
.. _Yara: http://code.google.com/p/yara-project/
.. _Libvirt: http://www.libvirt.org
.. _Bottlepy: http://www.bottlepy.org
.. _Pefile: http://code.google.com/p/pefile/

Virtualization Software
=======================

Despite heavily relying on `VirtualBox`_ in the past, Cuckoo has moved on being
architecturally independent from the virtualization software.
As you will see throughout this documentation, you'll be able to define and write
modules to support any software of your choice.

For the sake of this guide we will assume that you have VirtualBox installed
(which still is the default option), but this does **not** affect anyhow the
execution and general configuration of the sandbox.

You are completely responsible for the choice, configuration and execution of
your virtualization software, therefore please hold from asking help on it in our
channels and lists: refer to the software's official documentation and support.

Assuming you decide to go for VirtualBox, you can get the proper package for
your distribution at the `official download page`_.
The installation of VirtualBox is not in the purpose of this documentation, if you
are not familiar with it please refer to the `official documentation`_.

.. _VirtualBox: http://www.virtualbox.org
.. _official download page: https://www.virtualbox.org/wiki/Linux_Downloads
.. _official documentation: https://www.virtualbox.org/wiki/Documentation

.. _installing_tcpdump:

Installing Tcpdump
==================

In order to dump the network activity performed by the malware during
execution, you'll need a network sniffer properly configured to capture
the traffic and dump it to a file.

By default Cuckoo adopts `tcpdump`_, the prominent open source solution.

Install it on Ubuntu::

    $ sudo apt-get install tcpdump

Tcpdump requires root privileges, but since you don't want Cuckoo to run as root
you'll have to set specific Linux capabilities to the binary::

    $ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

You can verify the results of last command with::

    $ getcap /usr/sbin/tcpdump 
    /usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip

If you don't have `setcap` installed you can get it with::

    $ sudo apt-get install libcap2-bin

Or otherwise (**not recommended**) do::

    $ sudo chmod +s /usr/sbin/tcpdump

.. _tcpdump: http://www.tcpdump.org

.. _installing_snort:

Installing Snort
================

As an optional additional module, Cuckoo can use Snort IDS to analyze the network traffic
and detect any alerts fired by it.

To install `Snort`_ on Ubuntu::

    $ sudo apt-get install snort

This command will also install some prerequisites and dependencies, among which
snort-rules-default (a default ruleset) and `oinkmaster`_, a tool to automatically download
and install new Snort rules from various open repositories.
    
Snort requires root privileges to run but, once it has been started, it can
be configured to change its user to a non-root one. To do this, Snort should
be started using ``sudo``, then we'll use the ``-u`` command line option to change the
running user. To configure your system to allow cuckoo's user to start Snort with
the sudo command without requiring a password, you should edit your sudoers file
with the following command::

    $ sudo visudo

Then add the following line near the end of the file, right before any ``#include`` and ``#includedir``
directive (assuming that your Cuckoo install is running with the username "cuckoo")::

    cuckoo ALL=NOPASSWD:/usr/bin/snort

You can check the correct path to the snort executable by running::

    $ which snort

If you are using this setup, please make sure that your networkanalyzer.conf file has the following
options enabled in the `snort` section::

    use_sudo = yes
    username = cuckoo

Please refer to :ref:`networkanalyzer_conf` to know how to do this.

.. _Snort: http://www.snort.org
.. _oinkmaster: http://oinkmaster.sourceforge.net