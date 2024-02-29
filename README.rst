=================================
Transparent Research Object utils
=================================


.. image:: https://img.shields.io/pypi/v/tro_utils.svg
        :target: https://pypi.python.org/pypi/tro_utils

.. image:: https://img.shields.io/travis/Xarthisius/tro_utils.svg
        :target: https://travis-ci.com/Xarthisius/tro_utils

.. image:: https://readthedocs.org/projects/tro-utils/badge/?version=latest
        :target: https://tro-utils.readthedocs.io/en/latest/?version=latest
        :alt: Documentation Status




Utilities for creating, editing and interacting with TROs


* Free software: BSD license
* Documentation: https://tro-utils.readthedocs.io.


Features
--------

* TODO

HOWTO
-----

Assumes that `/tmp/foo/1` and `/tmp/foo/2` exists with some files, this package is installed 
and your GPG key is present::

   $ cd /tmp
   $ export GPG_FINGERPRINT=...
   $ export GPG_PASSPHRASE=...
   $ tro-utils arrangement add /tmp/foo/1  # creates /tmp/some_tro.jsonld that can be inspected
   $ tro-utils arrangement add /tmp/foo/2
   $ tro-utils sign
   $ tro-utils verify

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
