Here’s the updated `README.md` file with the "Pulling KMS Keys" section moved ahead of "Encrypting Files" in the Usage section:

---

# spartan-git-secret-protector

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

Before using the tool, ensure you have the necessary AWS permissions to manage KMS keys. Then, initialize your repository for secret protection by installing Git hooks and setting up the module:

```sh
git_secret_protector install
```

### 2. Pulling KMS Keys

Before encrypting or decrypting files, you need to pull the relevant KMS keys for a specific filter:

```sh
git_secret_protector pull-kms-key <filter_name>
```

This command will pull the latest AES data key from AWS KMS for the specified filter and cache it locally.

### 3. Encrypting Files

To encrypt files in your repository:

```sh
git_secret_protector encrypt <filter_name>
```

The tool will automatically detect files based on the patterns defined in your `.gitattributes` file for the specified filter and encrypt them using the appropriate AES data key.

### 4. Decrypting Files

To decrypt files:

```sh
git_secret_protector decrypt <filter_name>
```

This command will decrypt the files in your working directory for the specified filter, making them available for editing.

### 5. Key Rotation

Rotate your AES data keys periodically for enhanced security:

```sh
git_secret_protector rotate-key <filter_name>
```

This command will generate a new AES data key in KMS, re-encrypt your files associated with the specified filter with the new key, and update the local cache.

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
