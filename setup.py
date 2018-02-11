"""
Flask-OAuth
-----------

Adds OAuth support to Flask.

Links
`````

* `documentation <http://packages.python.org/Flask-OAuth>`_
* `development version
  <http://github.com/mitsuhiko/flask-oauth/zipball/master#egg=Flask-OAuth-dev>`_
"""
from setuptools import setup


setup(
    name='Flask-OAuth',
    version='0.13',
    url='http://github.com/mitsuhiko/flask-oauth',
    license='BSD',
    author='Armin Ronacher',
    author_email='armin.ronacher@active-4.com',
    description='Adds OAuth support to Flask',
    long_description=__doc__,
    py_modules=['flask_oauth'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'Flask',
        'oauth2'
    ],
    dependency_links=[
        'git+ssh://git@github.com:i-kiwamu/python3-oauth2.git#egg=oauth2'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
