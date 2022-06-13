Okdata Maskinporten API
==================

REST API for managing clients and keys in [Maskinporten](https://samarbeid.digdir.no/maskinporten/maskinporten/25) and synchronization with AWS SSM.

## Setup

In these examples, we use the default `python3` distribution on your platform.
If you need a specific version of python you need to run the command for that
specific version. Ie. for 3.8 run `python3.9 -m venv .venv` instead to get a
virtualenv for that version.

### Installing global python dependencies

You can either install globally. This might require you to run as root (use sudo).

```bash
python3 -m pip install tox black pip-tools
```

Or, you can install for just your user. This is recommended as it does not
require root/sudo, but it does require `~/.local/bin` to be added to `PATH` in
your `.bashrc` or similar file for your shell. Eg:
`PATH=${HOME}/.local/bin:${PATH}`.

```bash
python3 -m pip install --user tox black pip-tools
```


### Installing local python dependencies in a virtualenv

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```bash
make init
```


## Tests

Tests are run using [tox](https://pypi.org/project/tox/): `make test`

For tests and linting we use [pytest](https://pypi.org/project/pytest/),
[flake8](https://pypi.org/project/flake8/) and
[black](https://pypi.org/project/black/).


## Deploy

Deploy to both dev and prod is automatic via GitHub Actions on push to main. You
can alternatively deploy from local machine with: `make deploy` or `make
deploy-prod`.


## Self-service

In order to open up for self service here, we will need to take some measures:

* Ensure that the user making the request is an Origo user (ooo123456)
* Ensure that the associated team is an Origo Team
    * This can be acquired by assigning this [Keycloak role](https://github.com/oslokommune/dataplatform-config/blob/main/devops/modules/keycloak-resource-server/main.tf#L121-L128) to origo-teams
    * Attaching roles to existing Origo teams can be done using the Keycloak console
    * Attaching roles to new teams can be done by extending the Teams API. An example can be found in [this branch](https://github.com/oslokommune/teams)
