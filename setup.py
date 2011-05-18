"""wire: Properly private messaging.

A solution to government-comprimised messaging services, by
providing a simple buy powerful user interface to communicate
messages and events between activists and groups.
"""

from distutils.core import setup

NAME='wire-bbs'
doclines = __doc__.split("\n")

files = ['static/*', 'templates/*']

setup(
    name=NAME,
    version = "0.1",
    description = doclines[0],
    long_description = "\n".join(doclines[2:]),
    url='https://github.com/radiosilence/wire',
    author='James E. Cleveland',
    author_email='jamescleveland@gmail.com',
    packages=['wire', 'wire.models', 'wire.utils'],
    license = "MIT",
    scripts = ["debug"],
    package_data = {'wire': files},
    requires = [
      'Flask',
      'redis',
      'json',
      'flaskext.markdown',
      'flaskext.uploads',
      'os', 'uuid', 'subprocess', 'shlex',
      'Crypto', 'base64'
    ],
    classifiers= [
      'Development Status :: 2 - Pre-Alpha',
      'Environment :: Web Environment',
      'Intended Audience :: Developers',
      'Intended Audience :: End Users/Desktop',
      'License :: OSI Approved :: MIT License',
      'Natural Language :: English',
      'Operating System :: POSIX :: Linux',
      'Programming Language :: Python',
      'Topic :: Communications :: BBS',
      'Topic :: Communications :: Chat',
      'Topic :: Internet :: WWW/HTTP :: Dynamic Content :: Message Boards',
      'Topic :: Security'
      ]
    )
