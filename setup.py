"""wire: Properly private messaging.

A solution to government-comprimised messaging services, by
providing a simple buy powerful user interface to communicate
messages and events between activists and groups.
"""

from setuptools import setup, find_packages
name='wire'
setup(
    name=name,
    version='0.1',
    url='https://github.com/radiosilence/wire',
    author='James E. Cleveland',
    author_email='jamescleveland@gmail.com',
    package_dir = {'': 'src'},
    packages=find_packages('src'),
    namespace_packages=['wire',],
    include_package_data = True,
    install_requires=['setuptools'],
    zip_safe = False,
    )