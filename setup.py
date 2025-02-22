##############################################################################
#
# Copyright (c) 2007-2009 Agendaless Consulting and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the BSD-like license at
# http://www.repoze.org/LICENSE.txt.  A copy of the license should accompany
# this distribution.  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL
# EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND
# FITNESS FOR A PARTICULAR PURPOSE
#
##############################################################################

import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
def _read_file(filename):
    try:
        with open(os.path.join(here, filename)) as f:
            return f.read()
    except IOError:  # Travis???
        return ''

README = _read_file('README.rst')
CHANGES = _read_file('CHANGES.rst')

setup(name='repoze.who',
      version='3.1.0',
      description=('repoze.who is an identification and authentication '
                   'framework for WSGI.'),
      long_description='\n\n'.join([README, CHANGES]),
      long_description_content_type="text/x-rst",
      classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      python_requires=">=3.9",
      keywords='web application server wsgi zope',
      author="Agendaless Consulting",
      author_email="repoze-dev@lists.repoze.org",
      url="http://www.repoze.org",
      license="BSD-derived (http://www.repoze.org/LICENSE.txt)",
      packages=find_packages(),
      include_package_data=True,
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      zip_safe=False,
      install_requires=[
        'WebOb',
        'zope.interface',
        'setuptools',
        'legacy-cgi; python_version > "3.12"',  # WebOb uses the cgi module
      ],
      test_suite="repoze.who",
      entry_points = """\
      [paste.filter_app_factory]
      test = repoze.who.middleware:make_test_middleware
      config = repoze.who.config:make_middleware_with_config
      predicate = repoze.who.restrict:make_predicate_restriction
      authenticated = repoze.who.restrict:make_authenticated_restriction
      """,
      extras_require = {
        'docs': ['Sphinx', 'repoze.sphinx.autointerface'],
      },
)
