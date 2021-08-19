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
    description="Blueprint for lambda function at Oslo Origo",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.oslo.kommune.no/origo-dataplatform/lambda-boilerplate",
    packages=find_packages(),
    install_requires=["aws-xray-sdk", "okdata-aws"],
)
