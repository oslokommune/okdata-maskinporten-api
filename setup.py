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
    description="REST API for managing clients and keys for public services and synchronization with AWS SSM",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/oslokommune/okdata-maskinporten-api",
    packages=find_packages(),
    install_requires=[
        "authlib>=1",
        "aws-xray-sdk>=2.12,<3",
        "boto3>=1.28.11,<2",
        "cryptography>=42.0.5,<45",
        "fastapi>=0.109.2",
        "mangum>=0.12.4,<1",
        "okdata-aws>=5",
        "okdata-resource-auth>=0.1.4",
        "pydantic>2,<3",
        "pyjwt>=2.7,<3",
        "python-keycloak",
        "requests>=2.28.0,<3",
    ],
    python_requires="==3.13.*",
)
