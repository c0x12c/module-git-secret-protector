# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Note**: Ensure to keep this changelog updated with every new release or change made to the project.

## [Unreleased]

### Added

### Changed

### Removed

## [0.2.0] - 2024-09-03

### Added
- Initial release of the `git_secret_protector` CLI tool.
- Support for setting up AES data keys in AWS KMS.
- Integration with `.gitattributes` for specifying secret files.
- CLI commands for key rotation, encryption, and decryption.
- Logging setup with configurable log file paths.
- Caching of KMS data keys for performance improvements.
- Unit and integration tests for core functionalities.
- Error handling and logging for better debugging and reliability.
- `key_refresher` for refreshing KMS data keys.

### Changed

### Fixed

### Removed
