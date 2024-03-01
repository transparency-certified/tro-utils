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

Assumes that:

*  `/tmp/foo/1` and `/tmp/foo/2` exists with some files
* this package is installed
* your GPG key is present
* `trs.jsonld` is available and defines TRS capabilities (see below for an example)

Example workflow::

   $ cd /tmp
   $ /tmp/foo $ tree .
     .
     ├── 1
     │   ├── input_data.csv
     │   └── run.sh
     └── 2
         ├── data
         │   └── output.dat
         ├── input_data.csv
         └── run.sh

     3 directories, 5 files

   $ cat /tmp/trs.jsonld
   $ cat trs.jsonld
     {
       "rdfs:comment": "TRS that can monitor netowrk accesses or provide Internet isolation",
       "trov:hasCapability": [
         {
           "@id": "trs/capability/1",
           "@type": "trov:CanRecordInternetAccess"
         },
         {
           "@id": "trs/capability/2",
           "@type": "trov:CanProvideInternetIsolation"
         }
       ]
     }
   $ export GPG_FINGERPRINT=...
   $ export GPG_PASSPHRASE=...
   # It's sufficient to pass the profile only once
   $ tro-utils --declaration magnificent_tro.jsonld --profile trs.jsonld arrangement add /tmp/foo/1
     Loading profile from trs.jsonld
   $ tro-utils --declaration magnificent_tro.jsonld arrangement list
     Arrangement(id=arrangement/0): Scanned /tmp/foo/1
   $ tro-utils --declaration magnificent_tro.jsonld arrangement add /tmp/foo/2 -m "Scanned folder after executing run.sh"
   $ tro-utils --declaration magnificent_tro.jsonld arrangement list
     Arrangement(id=arrangement/0): Scanned /tmp/foo/1
     Arrangement(id=arrangement/1): Scanned folder after executing run.sh
   $ tro-utils --declaration magnificent_tro.jsonld performance add \
     -m "My magic workflow" \
     -s 2024-03-01T09:22:01 \
     -e 2024-03-02T10:00:11 \
     -c trov:InternetIsolation \
     -c trov:InternetAccessRecording \
     -a arrangement/0 \
     -a arrangement/1
    $ tro-utils --declaration magnificent_tro.jsonld sign
    $ tro-utils --declaration magnificent_tro.jsonld verify
      Using configuration from /usr/lib/ssl/openssl.cnf
      Warning: certificate from '/tmp/tmpsew5qrk8' with subject '/O=Free TSA/OU=TSA/description=This certificate digitally signs documents and time stamp requests made using the freetsa.org online services/CN=www.freetsa.org/emailAddress=busilezas@gmail.com/L=Wuerzburg/C=DE/ST=Bayern' is not a CA cert
      Verification: OK

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
