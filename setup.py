"""
Django-MongoEngine
------------------

Django support for MongoDB using MongoEngine.

Links
`````

* `development version
  <https://github.com/MongoEngine/django-mongoengine/raw/master#egg=Django-MongoEngine-dev>`_

"""
from setuptools import setup, find_packages
import sys, os


__name__ = 'ericsson-django-mongoengine'
# use 0.2.1xx  format, last two digits are for ericsson custom
# RPMs for Integration team does not work with packages version number with more than x.y.z digits
__version__ = '0.2.107'
__description__ = 'Django support for MongoDB via MongoEngine'
__license__ = 'BSD'
__author__ = 'Ross Lawley'
__email__ = 'ross.lawley@gmail.com'


sys.path.insert(0, os.path.dirname(__file__))


REQUIRES = [i.strip() for i in open("requirements.txt").readlines()]


setup(
    name=__name__,
    version=__version__,
    url='https://github.com/mongoengine/django-mongoengine',
    download_url='https://github.com/mongoengine/django-mongoengine/tarball/master',
    license=__license__,
    author=__author__,
    author_email=__email__,
    description=__description__,
    long_description=__doc__,
    test_suite='nose.collector',
    zip_safe=False,
    platforms='any',
    install_requires=REQUIRES,
    packages=find_packages(exclude=('doc', 'docs',)),
    include_package_data=True,
    # use python setup.py nosetests to test
    setup_requires=['nose', 'coverage'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Framework :: Django'
    ]
)
