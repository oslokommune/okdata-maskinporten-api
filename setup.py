import os

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

service_name = os.path.basename(os.getcwd())

setup(
    name=service_name,
    version="0.1.0",
    author="Origo Dataplattform",
    author_email="dataplattform@oslo.kommune.no",
    description="REST API for managing clients and keys in Maskinporten and synchronization with AWS SSM",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/oslokommune/okdata-maskinporten-api",
    packages=find_packages(),
    install_requires=[
        "authlib",
        "aws-xray-sdk>=2.12,<3",
        "boto3>=1.28.11,<2",
        "cryptography>=42.0.5,<43",
        "fastapi>=0.109.2",
        "mangum>=0.12.4,<1",
        "okdata-aws>=4,<5",
        "okdata-resource-auth>=0.1.4",
        "pydantic>2,<3",
        "pyjwt>=2.7,<3",
        # Not needed directly (it's required by `python-keycloak`), but require
        # version 3.3.0 or higher explicitly to silence some deprecation
        # warnings.
        "python-jose>=3.3.0,<4.0.0",
        "python-keycloak>=1,<2",
        "requests>=2.28.0,<3",
        # We don't really need this, but AWS Lambda started including this
        # library in the Python 3.9 runtime, and `requests` will swap the
        # standard library `json` out for it when it's present in the
        # environment. Include it here explicitly so we are sure which JSON
        # library `requests` picks.
        #
        # TODO: Remove once `requests` 3.0.0 is out, since `simplejson` support
        # is dropped there.
        "simplejson>=3.18.1,<4",
    ],
)
