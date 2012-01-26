"""
====
wire
====

*Properly private messaging*

A solution to government-comprimised messaging services, by providing a simple
but powerful user interface to communicate messages and events between
activists and groups.
"""

from setuptools import setup, find_packages

NAME = 'wire-bbs'

setup(
    name=NAME,
    version="0.0.2",
    description='Activist socialising and organisation tool.',
    long_description=open('README.rst').read(),
    url='https://github.com/radiosilence/wire',
    author='James Cleveland',
    author_email='jamescleveland@gmail.com',
    packages=['wire'],
    license="LICENSE.txt",
    package_data={
        '': ['*.txt', '*.rst']
    },
    install_requires=open('requirements.txt').read().split("\n"),
    classifiers=[
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
