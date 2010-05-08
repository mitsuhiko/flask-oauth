"""
Flask-OAuth
-----------

Description goes here...

Links
`````

* `documentation <http://packages.python.org/Flask-OAuth`_
* `development version
  <http://github.com/USERNAME/REPOSITORY/zipball/master#egg=Flask-OAuth-dev>`_

"""
from setuptools import setup


setup(
    name='Flask-OAuth',
    version='0.1',
    url='<enter URL here>',
    license='BSD',
    author='Armin Ronacher',
    description='<enter short description here>',
    long_description=__doc__,
    packages=['flaskext'],
    namespace_packages=['flaskext'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'Flask',
        'oauth2'
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
