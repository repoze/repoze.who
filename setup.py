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
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

setup(name='repoze.who',
      version='2.0b1',
      description=('repoze.who is an identification and authentication '
                   'framework for WSGI.'),
      long_description='\n\n'.join([README, CHANGES]),
      classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      keywords='web application server wsgi zope',
      author="Agendaless Consulting",
      author_email="repoze-dev@lists.repoze.org",
      url="http://www.repoze.org",
      license="BSD-derived (http://www.repoze.org/LICENSE.txt)",
      packages=find_packages(),
      include_package_data=True,
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      zip_safe=False,
      tests_require = ['Paste', 'zope.interface'],
      install_requires=['Paste', 'zope.interface', 'setuptools'],
      test_suite="repoze.who",
      entry_points = """\
      [paste.filter_app_factory]
      test = repoze.who.middleware:make_test_middleware
      config = repoze.who.config:make_middleware_with_config
      predicate = repoze.who.restrict:make_predicate_restriction
      authenticated = repoze.who.restrict:make_authenticated_restriction
      """
)

