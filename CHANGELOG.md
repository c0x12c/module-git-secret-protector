# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Note**: Ensure to keep this changelog updated with every new release or change made to the project.

## [Unreleased]

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
