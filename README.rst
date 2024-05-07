=================================
Transparent Research Object utils
=================================

.. image:: https://img.shields.io/pypi/v/tro_utils.svg
        :target: https://pypi.python.org/pypi/tro-utils

.. image:: https://img.shields.io/travis/transparency-certified/tro-utils.svg
        :target: https://travis-ci.com/transparency-certified/tro-utils

.. image:: https://readthedocs.org/projects/tro-utils/badge/?version=latest
        :target: https://tro-utils.readthedocs.io/en/latest/?version=latest
        :alt: Documentation Status

This package provides a set of utilities for working with Transparent Research Objects (TROs). It is designed to be used in
conjunction with the `TRO specification <https://transparency-certified.github.io/trace-specification/docs/specifications/tro/0.1/index.html>`_.

It uses the ``Click`` library to define commands and options. Here's a summary of the main features:

1. **Global Options**: The script defines several global options that can be used with any command,
   such as ``--declaration``, ``--profile``, ``--gpg-fingerprint``, ``--gpg-passphrase``, ``--tro-creator``,
   ``--tro-name``, and ``--tro-description``. These options can be used to specify various parameters for the TRO.

1. **Commands**: The script defines several commands, each with its own set of options and arguments. The commands include:

   - ``verify``: Verifies that the TRO is signed and timestamped correctly.

   - ``arrangement``: Manages arrangements in the TRO. It has subcommands like ``add`` (adds a directory as a composition to the TRO)
     and ``list`` (lists available arrangements in the TRO).

   - ``composition``: Manages compositions in the TRO. It has a subcommand ``info`` that gets info about the current composition.

   - ``performance``: Manages performances in the TRO. It has a subcommand ``add`` that adds a performance to the TRO.

   - ``sign``: Signs the TRO.

   - ``report``: Generates a report of the TRO.

1. **TRO Interaction**: The script interacts with the TRO using the ``TRO`` class from the ``tro_utils`` module.
   It uses this class to create a new TRO, add arrangements and performances to the TRO, verify the TRO,
   and generate a report of the TRO.

Example Usage
-------------

Assumes that:

* this package is installed
* your GPG key is present
* ``trs.jsonld`` is available and defines TRS capabilities (see below for an example)

Example workflow::

   $ cd /tmp
   $ cat trs.jsonld
     {
       "rdfs:comment": "TRS that can monitor netowork accesses or provide Internet isolation",
       "trov:hasCapability": [
         {
           "@id": "trs/capability/1",
           "@type": "trov:CanRecordInternetAccess"
         },
         {
           "@id": "trs/capability/2",
           "@type": "trov:CanProvideInternetIsolation"
         }
       ],
       "trov:owner": "Kacper Kowalik",
       "trov:description": "My local system",
       "trov:contact": "root@dev.null",
       "trov:url": "http://127.0.0.1/",
       "trov:name": "shakuras"
     }
   $ export GPG_FINGERPRINT=...
   $ export GPG_PASSPHRASE=...
   $ git clone https://github.com/transparency-certified/sample-trace-workflow /tmp/sample
   # It's sufficient to pass the profile only once
   $ tro-utils --declaration sample_tro.jsonld --profile trs.jsonld arrangement add /tmp/sample \
       -m "Before executing workflow" -i .git
     Loading profile from trs.jsonld
   $ tro-utils --declaration sample_tro.jsonld arrangement list
     Arrangement(id=arrangement/0): Before executing workflow
   $ pushd /tmp/sample && \
     docker build -t xarthisius/sample . && \
     ./run_locally.sh latest xarthisius && \
     popd
   $ tro-utils --declaration sample_tro.jsonld arrangement add /tmp/sample \
       -m "After executing workflow" -i .git
   $ tro-utils --declaration sample_tro.jsonld arrangement list
     Arrangement(id=arrangement/0): Before executing workflow
     Arrangement(id=arrangement/1): After executing workflow
   $ tro-utils --declaration sample_tro.jsonld performance add \
     -m "My magic workflow" \
     -s 2024-03-01T09:22:01 \
     -e 2024-03-02T10:00:11 \
     -c trov:InternetIsolation \
     -c trov:InternetAccessRecording \
     -a arrangement/0 \
     -M arrangement/1
    $ tro-utils --declaration sample_tro.jsonld sign
    $ tro-utils --declaration sample_tro.jsonld verify
      ...
      Verification: OK
    $ curl -LO https://raw.githubusercontent.com/craig-willis/trace-report/main/templates/tro.md.jinja2
    $ tro-utils --declaration sample_tro.jsonld report --template tro.md.jinja2 -o report.md


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
