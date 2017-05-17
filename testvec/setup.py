#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        # self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        pytest.main(self.test_args)

setup(
    name='p2pdraft',
    version='0.1',
    packages=[],
    include_package_data=True,
    install_requires=['ecdsa', 'pysha3', 'rlp', 'bitcoin'],
    license="MIT",
    zip_safe=False,
    cmdclass={'test': PyTest},
    tests_require=['pytest'],
)
