# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Note**: Ensure to keep this changelog updated with every new release or change made to the project.

## [1.2.4] - 2025-03-30
- Bump version to v1.2.4

## [1.2.0] - 2025-03-30

### Changed

- Improved AES decryption error message.
- Include short AWS region in SSM parameter names.

## [1.1.1] - 2025-01-01

### Changed

- Removed redundant code for retrieving the project ID using the gcloud CLI.
- Upgraded dependencies.

## [1.1.0] - 2024-11-11

### Changed

- Retrieve GCP Project ID from default credentials.

### Removed
- Remove the legacy parameter key in AWS Parameter Store.

## [1.0.2] - 2024-10-21

### Changed

- Bump version to `v1.0.2`.

## [1.0.1] - 2024-10-21

### Changed

- Get project version from the module metadata.

## [1.0.0] - 2024-10-21

### Changed

- Add `aws_account_id` to parameter name to prevent mistakenly pulling the AES key from another project.
- Add `version` command, which returns the current module version.
  Add AWS Account ID to AWS parameter name

## [0.8.0] - 2024-10-20

### Added

- Add `clean-filter` command, which allows the cleaning of staged data for a specified filter.

## [0.7.0] - 2024-10-20

### Changed

- Enhance logging to provide detailed diagnostic messages and return user-friendly error messages to the client.

## [0.6.0] - 2024-09-12

### Added
- Replace `init` command with `setup-filters` command to configure Git filters.

## [0.5.0] - 2024-09-11

### Added
- Added support for storing AES data keys in GCP Secret Manager.

## [0.4.0] - 2024-09-05

### Added
- Add a `encrypt-files` command to encrypt all files under a specific filter.

## [0.3.0] - 2024-09-05

### Added
- Add a `decrypt-files` command to decrypt all files under a specific filter.
- Create config.ini when initializing the module
- Add caching for Poetry in the PR check pipeline

### Changed
- Separate the init command into two commands: `init` and `setup-aes-key`.

## [0.2.0] - 2024-09-03

### Added
- Initial release of the `git-secret-protector` CLI tool.
- Support for setting up AES data keys in AWS Parameter Store.
- Integration with `.gitattributes` for specifying secret files.
- CLI commands for key rotation, encryption, and decryption.
- Caching of AES data keys for performance improvements.
- Unit and integration tests for core functionalities.
- Error handling and logging for better debugging and reliability.
- Add `init` command to set up the initial configuration.
- Add `status` command to view the encryption status of files.

### Changed

### Fixed

### Removed
