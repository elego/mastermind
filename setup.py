"""CLI to easily intercept and mock HTTP requests.

See:
https://github.com/ustwo/mastermind
"""

from setuptools import setup, find_packages
from codecs import open
from os import path
from mastermind.version import VERSION

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='mastermind',
    version=VERSION,
    description='CLI to easily intercept and mock HTTP requests',
    long_description=long_description,
    url='https://github.com/ustwo/mastermind',
    author='ustwo',
    author_email='open.source@ustwo.com',
    license='MIT',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    packages=find_packages(),
    install_requires=['mitmproxy==4.0.4',
                      'Flask==1.0.2',
                      'PyYAML==5.1',
                      'jsonschema==3.0.1',
                      'coloredlogs==10.0',
                      'pytoml==0.1.20',
                      'tinydb==3.13.0'],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        # 'dev': ['check-manifest'],
        'test': ['nose'],
    },

    # If there are data files included in your packages that need to be
    # installed, specify them here.  If using Python 2.6 or less, then these
    # have to be included in MANIFEST.in as well.
    # package_data={
    #     'sample': ['package_data.dat'],
    # },
    package_data={'mastermind': ['scripts/*.py']},

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        'console_scripts': [
            'proxyswitch=mastermind.proxyswitch:main',
            'mastermind=mastermind.main:main',
        ],
    },
)
