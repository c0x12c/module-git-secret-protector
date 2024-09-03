# Basic Usage Example

This example demonstrates how to use the `git-secret-protector` module to manage secrets within a Git repository.

## Setup

1. **Install the Module:**

   Install the `git_secret_protector` module via pip:

   ```sh
   pip install git_secret_protector
   ```
2. **Initialize the Repository:**

   Install Git hooks and initialize the module:

   ```sh
   git_secret_protector install
   ```

3. **Setup AES key:**

   Set up an AES key in AWS KMS for the sample-app filter:

   ```sh
   git_secret_protector setup-aes-key sample-app
   ```

4. **Pull KMS Key:**
   Pull the KMS key for the sample-app filter:

   ```sh
   git_secret_protector pull-kms-key sample-app
   ```

5. **Encrypt Files:**

   Encrypt the files defined in the .gitattributes file:

   ```sh
   git_secret_protector encrypt sample-app
   ```

6. **Decrypt Files:**

   Decrypt the files when you need to view or edit them:

   ```sh
   git_secret_protector decrypt sample-app
   ```

## Configuration
The config.ini file contains the settings for the git_secret_protector module. You can customize these settings as needed.

## Logging
Logs are stored in the .git_secret_protector/logs directory by default. You can view these logs to track the operations and any errors.

## Notes
- Make sure you have the necessary AWS permissions to create and manage KMS keys.
- This example assumes that you have AWS credentials configured in your environment.

```
### Summary

The `/examples/basic-usage` folder provides a simple, clear example of how to use the `git-secret-protector` module with the `sample-app` filter name. It demonstrates how to configure the module, encrypt and decrypt files, and manage keys with AWS KMS. This example should serve as a helpful starting point for users who want to integrate the module into their own projects.
```
