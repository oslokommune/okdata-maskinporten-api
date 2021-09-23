import os


def getenv(name):
    """Return the environment variable named `name`.

    Raise `OSError` if it's unset.
    """
    env = os.getenv(name)

    if env is None:
        raise OSError(f"Environment variable {name} is not set")

    return env
