# git-secret-protector

`spartan-git-secret-protector` is a Python-based CLI tool designed to securely manage and protect sensitive files in your Git repositories. It integrates with AWS Parameter Store to encrypt and decrypt secrets, ensuring that your sensitive data remains secure throughout your development process.

## Features

- **AES Key Management**: Securely create, manage, and rotate AES data keys using AWS Parameter Store.
- **File Encryption/Decryption**: Automatically encrypt and decrypt files in your repository based on patterns defined in the `.gitattributes` file.
- **Cache Management**: Cache AES data keys locally to improve performance and reduce redundant calls to AWS Parameter Store.
- **Git Hooks Integration**: Integrates with Git hooks to automatically manage secrets during Git operations.
- **Logging**: Configurable logging for detailed tracking of operations and errors.

## Install Guide

### Requirements

- pipx ([Download](https://pipx.pypa.io/stable/installation/))

You can install the `git-secret-protector` module via pipx:

```sh
pipx install git-secret-protector
```

## Usage

### 1. Initial Setup

#### Set up AES key

Before using the tool, ensure you have the necessary AWS permissions to manage AWS MKS & SSM.

```sh
git-secret-protector init <filter_name>
```

**NOTE: Perform this setup once per repository during initial configuration.**

### 2. Configure Git Filters

onfigure the Git clean and smudge filters for the specified filter name

```sh
git-secret-protector init <filter_name>
```

### 3. Pull AES Key and IV

Before encrypting or decrypting files, it's necessary to retrieve the relevant AES keys from the AWS Parameter Store for specific filters:

```sh
git-secret-protector pull-aes-key <filter_name>
```

This command fetches the latest AES data key and IV from AWS Parameter Store for the designated filter and caches them locally for subsequent operations. This step ensures that you have the correct keys for encryption or decryption tasks related to the specified filter.

### 4. Key Rotation

#### Command to Rotate Keys

```sh
git-secret-protector rotate-key <filter_name>
```

This command will generate a new AES data key in AWS Parameter Store, re-encrypt your files associated with the specified filter with the new key, and update the local cache.

#### Post-Rotation Code Reset
After rotating the keys, it is necessary to clear the Git cache and re-checkout all files. This step ensures that the smudge filters are triggered, allowing the files to be decrypted with the new key.

```
# Remove all files from the index to clear the Git cache
git rm --cached -r .

# Force Git to re-checkout all files, triggering smudge filters
git reset --hard
```

### 5. View Encryption Status

Command to obtain a comprehensive overview of the encryption status of files within the repository:

```sh
git-secret-protector status
```

## Configuration

All configurations are managed through a `config.ini` file located in the `.git-secret-protector` directory. You can customize the following settings:

- **Logging**: Configure the log file path and rotation settings.
- **Module Name**: Specify a custom module name for organizing keys in AWS Parameter Store.

### Example `.gitattributes` File

Define which files to encrypt in your `.gitattributes` file:

```
secrets/*.tfstate filter=sample-app diff=sample-app
config/**/credentials/* filter=sample-shared diff=sample-shared
```

### Logging

Logs are stored in the `logs/` directory by default, and you can configure the log level and file rotation in the `config.ini` file.

## Development

### Running Tests

- **Unit Tests**: Located in the `tests/unit` directory, run them using `pytest`.
- **Integration Tests**: Located in the `tests/integration` directory, these tests interact with AWS Parameter Store and should be run manually.

```sh
poetry run pytest tests/unit
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a history of changes and updates.

## Support

If you encounter any issues or have any questions, please open an issue on the GitHub repository or reach out to our support team.
