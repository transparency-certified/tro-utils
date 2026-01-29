# Installation

## Pre-requisites
Before you begin, you need to have the following installed on your system:

- GPG
- OpenSSL
- Python 3.8+

You can do this by running the following commands:

```bash
$ sudo apt-get install gnupg openssl python3 python3-pip    # on Debian/Ubuntu
$ brew install gnupg openssl python3                        # on macOS with Homebrew
```

## Stable release

To install Transparent Research Object utils, run this command in your terminal:

```console
$ pip install tro_utils
```

This is the preferred method to install Transparent Research Object utils, as it will always install the most recent stable release.

If you don't have [pip](https://pip.pypa.io) installed, this [Python installation guide](http://docs.python-guide.org/en/latest/starting/installation/) can guide you through the process.

## From sources

The sources for Transparent Research Object utils can be downloaded from the [Github repo](https://github.com/Xarthisius/tro_utils).

You can either clone the public repository:

```console
$ git clone git://github.com/Xarthisius/tro_utils
```

Or download the [tarball](https://github.com/Xarthisius/tro_utils/tarball/master):

```console
$ curl -OJL https://github.com/Xarthisius/tro_utils/tarball/master
```

Once you have a copy of the source, you can install it with:

```console
$ python setup.py install
```
