# git-secret-protector

`spartan-git_secret_protector` is a Python-based CLI tool designed to securely manage and protect sensitive files in your Git repositories. It integrates with AWS KMS to encrypt and decrypt secrets, ensuring that your sensitive data remains secure throughout your development process.

## Features

- **AES Key Management**: Securely create, manage, and rotate AES data keys using AWS KMS.
- **File Encryption/Decryption**: Automatically encrypt and decrypt files in your repository based on patterns defined in the `.gitattributes` file.
- **Cache Management**: Cache KMS data keys locally to improve performance and reduce redundant calls to AWS KMS.
- **Git Hooks Integration**: Integrates with Git hooks to automatically manage secrets during Git operations.
- **Logging**: Configurable logging for detailed tracking of operations and errors.

## Installation

You can install the `git_secret_protector` module via pip:

```sh
pip install git_secret_protector
```

## Usage

### 1. Initial Setup

Before using the tool, ensure you have the necessary AWS permissions to manage AWS MKS & SSM. Then, initialize your repository for secret protection by installing Git clean and smudge filter and setting up the module.

```sh
git_secret_protector install
```

### 2. Pull AES Key

Before encrypting or decrypting files, you need to pull the relevant KMS keys for a specific filter:

```sh
git_secret_protector pull-aes-key <filter_name>
```

This command will pull the latest AES data key from AWS KMS for the specified filter and cache it locally.

This command will decrypt the files in your working directory for the specified filter, making them available for editing.

### 3. Key Rotation

#### Command to Rotate Keys

```sh
git_secret_protector rotate-key <filter_name>
```

This command will generate a new AES data key in KMS, re-encrypt your files associated with the specified filter with the new key, and update the local cache.

#### Post-Rotation Code Reset
After rotating the keys, it is necessary to clear the Git cache and re-checkout all files. This step ensures that the smudge filters are triggered, allowing the files to be decrypted with the new key.

```
# Remove all files from the index to clear the Git cache
git rm --cached -r .

# Force Git to re-checkout all files, triggering smudge filters
git reset --hard
```

### Configuration

All configurations are managed through a `config.ini` file located in the `.git_secret_protector` directory. You can customize the following settings:

- **AWS Configuration**: Set your AWS region, profile, and other credentials.
- **Logging**: Configure the log file path and rotation settings.
- **Module Name**: Specify a custom module name for organizing keys in AWS KMS.

### Example `.gitattributes` File

Define which files to encrypt in your `.gitattributes` file:

```
secrets/*.tfstate filter=git-crypt-app diff=git-crypt-app
config/**/credentials/* filter=git-crypt-shared diff=git-crypt-shared
```

### Logging

Logs are stored in the `logs/` directory by default, and you can configure the log level and file rotation in the `config.ini` file.

## Development

### Running Tests

- **Unit Tests**: Located in the `tests/unit` directory, run them using `pytest`.
- **Integration Tests**: Located in the `tests/integration` directory, these tests interact with AWS KMS and should be run manually.

```sh
poetry run pytest tests/unit
```

### Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute.

## License

`git_secret_protector` is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a history of changes and updates.

## Support

If you encounter any issues or have any questions, please open an issue on the GitHub repository or reach out to our support team.
