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

* this package is installed
* your GPG key is present
* `trs.jsonld` is available and defines TRS capabilities (see below for an example)

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
      Using configuration from /usr/lib/ssl/openssl.cnf
      Warning: certificate from '/tmp/tmpsew5qrk8' with subject '/O=Free TSA/OU=TSA/description=This certificate digitally signs documents and time stamp requests made using the freetsa.org online services/CN=www.freetsa.org/emailAddress=busilezas@gmail.com/L=Wuerzburg/C=DE/ST=Bayern' is not a CA cert
      Verification: OK
    $ curl -LO https://raw.githubusercontent.com/craig-willis/trace-report/main/templates/tro.md.jinja2
    $ tro-utils --declaration sample_tro.jsonld report --template tro.md.jinja2 -o report.md


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
