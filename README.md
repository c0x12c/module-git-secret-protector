# git-secret-protector

`git-secret-protector` is a Python-based CLI tool designed to securely manage and protect sensitive files in your Git repositories. It integrates with Cloud Secret Storage Services to encrypt and decrypt secrets, ensuring that your sensitive data remains secure throughout your development process.

## Features

- **AES Key Management**: Securely create, manage, and rotate AES data keys using Cloud Secret Storage Services such as AWS Parameter Store, Google Cloud Secret Manager.
- **File Encryption/Decryption**: Automatically encrypt and decrypt files in your repository based on patterns defined in the `.gitattributes` file.
- **Cache Management**: Cache AES data keys locally to improve performance and reduce redundant calls to Cloud Services.

## Install Guide

### Requirements

- pipx ([Download](https://pipx.pypa.io/stable/installation/))

- You can install the `git-secret-protector` module via pipx:

  ```sh
  pipx install git-secret-protector
  ```

## Usage

### 1. Initial Setup for Repositories Owners

#### 1.1. Create .gitattributes file

- Create a `.gitattributes` file in the root of your repository to define which files should be encrypted.

  Sample `.gitattributes` file:

  ```
  dev/secrets* filter=sample-app-dev diff=sample-app-dev
  
  prod/secrets* filter=sample-app-prod diff=sample-app-prod
  
  .gitattributes !filter !diff
  ```

#### 1.2. Configure Git Filters

- Set up the Git clean and smudge filters base on the filters defined in the `.gitattributes` file.

  ```sh
  git-secret-protector setup-filters
  ```

This command will configure the Git clean and smudge filters based on the patterns defined in the `.gitattributes` file. The filters will automatically encrypt and decrypt files based on the specified patterns.

- You can verify the configured filters in the `.git/config` file, for example:

   ```ini
   [filter "sample-app-dev"]
       clean = git-secret-protector encrypt sample-app-dev
       smudge = git-secret-protector decrypt sample-app-dev
       required = true
   ```

#### 1.3. Configuration

The `config.ini` file contains settings that customize the behavior of the `git-secret-protector` module. The file should be located in the module's directory (by default: `.git_secret_protector/config.ini`) and can be used to override the default values set in the code.

- Sample `config.ini`

  ```ini
  [DEFAULT]
  module_name = git-secret-protector
  log_file = /path/to/log/git_secret_protector.log
  log_level = INFO
  log_max_size = 1048576
  log_backup_count = 3
  magic_header = ENCRYPTED
  storage_type = AWS_SSM
  ```
- Configuration Parameters

  - `module_name`: Name of the module.
  - `log_file`: Path to the log file.
  - `log_level`: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
  - `log_max_size`: Maximum size of the log file in bytes.
  - `log_backup_count`: Number of log files to keep.
  - `magic_header`: Magic header to identify encrypted files.
  - `storage_type`: Cloud Secret Storage Service to use (AWS_SSM, GCP_SECRET_MANAGER).
    - AWS_SSM (default): AWS Parameter Store
    - GCP_SECRET: Google Cloud Secret Manager

#### 1.4. Set up AES key

**Notes:** 
Before executing this command, ensure you have the necessary permissions to manage resources in the using Cloud Secret Storage Services.

- Command to set up AES key

  ```sh
  git-secret-protector setup-aes-key <filter_name>
  ```

- Sample command to set up an AES key for the `sample-app-dev` filter:

  ```sh
  git-secret-protector setup-aes-key sample-app-dev
  ```

#### 1.5. Verify filter functionality

- Ensure that files are properly encrypted or decrypted by running:

  ```sh
  git-secret-protector status
  ```

The status will display the files managed by the filter and their encryption status.

### 2. Installation Steps for Team Members

#### 2.1. Pull AES Key and IV

**Notes**
Before encrypting or decrypting files, it's necessary to retrieve the relevant AES keys from the Cloud Secret Storage Service for filters:

- Command to pull AES key
  ```sh
  git-secret-protector pull-aes-key <filter_name>
  ```

This command fetches the latest AES data key and IV from the Cloud Secret Storage Service for the designated filter and caches them locally for subsequent operations. This step ensures that you have the correct keys for encryption or decryption tasks related to the specified filter.

#### 2.2. Configure Git Filters

- Set up the Git clean and smudge filters base on the filters defined in the `.gitattributes` file.

  ```sh
  git-secret-protector setup-filters
  ```

  Refer to [1.2. Configure Git Filters](#12-configure-git-filters) for instructions to verify if filters have been configured properly.

#### 2.2. Decrypt secret files

- Command to decrypt secret files:

  ```sh
  git-secret-protector decrypt-files <filter_name>
  ```

### 3. Common Usages

#### 3.1. Add a File to a filter's managed list

- **Add the file**

  Update the `.gitattributes` file to include the file under a path that matches a filter pattern. For example, to add `live/dev/secret.auto.tfvars`, update the `.gitattributes` file as follows:

  ```text
  live/dev/secret*.auto.tfvars filter=sample-app-dev diff=sample-app-dev
  ```

- **Encrypt the file**

  Use the following command to encrypt the file under the specified filter:

  ```sh
  git-secret-protector encrypt-files <filter>
  ```
  Replace `<filter>` with the name of the filter (e.g., `sample-app-dev`).

- **Verify encryption**

  Confirm that the file has been encrypted by running:

  ```sh
  git-secret-protector status
  ```

  Sample output
  ```
  Filter: sample-app-dev
    ./live/dev/secrets.auto.tfvars: Encrypted
    ./config/slack/secrets.tf: Encrypted
  Filter: sample-app-prod
    ...
  ```

- **Review before creating pull requests**

  Inspect the pull request to ensure encrypted files are included. Verify everything is correct before clicking the `Create pull request` button.

#### 3.2. Key Rotation

In case you need to rotate the AES key due to security reasons or a team member leaving the project, you can rotate the keys using the following command:

- Command to Rotate Keys

  ```sh
  git-secret-protector rotate-key <filter_name>
  ```

- This command will execute the following steps:
  - Generate a new AES data key in AWS Parameter Store
  - Re-encrypt your files associated with the specified filter with the new key
  - Update the local cache.


- Post-Rotation Code Reset

  After rotating the keys, it is necessary to clear the Git cache and re-checkout all files. This step ensures that the smudge filters are triggered, allowing the files to be decrypted with the new key.

  ```
  # Remove all files from the index to clear the Git cache
  git rm --cached -r .
  
  # Force Git to re-checkout all files, triggering smudge filters
  git reset --hard
  ```

### 4. Logging

Logs are stored in the `.git_secret_protector/logs/` directory by default, and you can configure the log level and file rotation in the `config.ini` file.

## Development

### Running Tests

- **Unit Tests**: Located in the `tests/unit` directory, run them using `pytest`.
  
  ```sh
  poetry run pytest tests/unit
  ```

- **Integration Tests**: Located in the `tests/integration` directory, these tests interact with Secret Store in cloud and should be run manually.

  ```sh
  poetry run pytest tests/integration
  ```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a history of changes and updates.

## Troubleshooting

If you encounter any issues while using the `git-secret-protector` tool, try the following tips and solutions:

### Common Issues

#### 1. Filter Configuration Issues

If the filters are not configured correctly, you might encounter errors when encrypting or decrypting files.

- **Solution**:
Re-setup the filters based on your `.gitattributes` file.

  ```sh
  git-secret-protector setup-filters
  ```

#### 2. Missing or Incorrect AES Key

If you fail to encrypt or decrypt files due to a missing or incorrect AES key, you will need to ensure that the keys are correctly fetched from the Cloud Secret Storage Service.

- **Solution**:
Pull the latest AES keys from the Cloud Secret Storage Service for the relevant filters.

  ```sh
  git-secret-protector pull-aes-key <filter_name>
  ```

#### 3. Permissions Issues

Lack of necessary permissions can result in errors while accessing Cloud Secret Storage Services.

- **Solution**:
Ensure that you have the required permissions to manage resources in your Cloud Secret Storage Service.

### Example Issue: File Decryption Failure

**Issue**:
You receive an error when trying to decrypt files using the `decrypt-files` command.

**Solution**:

- Ensure that you have pulled the latest AES keys:

  ```sh
  git-secret-protector pull-aes-key <filter_name>
  ```

- Check if the filters are correctly set up:

  ```sh
  git-secret-protector setup-filters
  ```

- Attempt to decrypt the files again:

  ```sh
  git-secret-protector decrypt-files <filter_name>
  ```

If the issue persists, verify your configurations in the `config.ini` file, and consult the logs located in the `logs/` directory for more detailed error information.
