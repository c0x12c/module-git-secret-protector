# Release Guidelines

To publish your Python module to GitHub Packages and allow developers to try it out, follow these steps:

## **Update Version**
Update the version number in pyproject.toml according to semantic versioning.

## **Set Up Twine**

- Install Twine

  ```bash
  pip install twine
  ```

- Configure .pypirc:

  Create a .pypirc file in your home directory (~/.pypirc):

  ```ini
  [distutils]
    index-servers =
    pypi

  [pypi]
    repository: https://upload.pypi.org/legacy/
    username: __token__
    password: your-token-here
  ```

- How It Works:
  - Repository: Specifies the PyPI repository URL.
  - Username: Typically set to `__token__` when using an API token.
  - Password: Enter your API token here. You can obtain it by following the [guidelines on PyPI](https://pypi.org/help/#apitoken).

## **Build the Package**

- Build your package using `Poetry`:

  ```bash
  poetry build
  ```

## **Publish to GitHub Packages**

- Publish the package using `twine`:
  ```bash
  twine upload dist/*
  ```
