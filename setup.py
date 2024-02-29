#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

requirements = [
    "Click>=7.0",
]

test_requirements = [
    "pytest>=3",
]

setup(
    author="Kacper Kowalik",
    author_email="xarthisius.kk@gmail.com",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="Utilities for creating, editing and interacting with TROs",
    entry_points={
        "console_scripts": [
            "tro-utils=tro_utils.cli:cli",
        ],
    },
    install_requires=requirements,
    license="BSD license",
    long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="tro_utils",
    name="tro_utils",
    packages=find_packages(include=["tro_utils", "tro_utils.*"]),
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/transparency-certified/tro-utils",
    version="0.1.0",
    zip_safe=False,
)
