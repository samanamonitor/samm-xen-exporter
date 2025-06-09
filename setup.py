from setuptools import setup, find_packages
from sammxenexporter import __version__
import re, os


if __name__ == "__main__":
    setup(
        name='sammxenexporter',
        version=__version__,
        packages=find_packages(include=['sammxenexporter', 'sammxenexporter.*']),
        scripts=[
            'scripts/exporter.py'
            ],
        data_files=[
            ('/app', [ 'config.json']),
            ('/usr/share/samm', [ 'requirements.txt' ] )
        ],
        install_requires=[ 
            "XenAPI",
            "prometheus_client"
        ]
    )
