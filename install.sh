#!/bin/bash

# Define repository URL and the desired tag
REPO_URL="https://github.com/c0x12c/git-secret-protector.git"
TAG="v0.1.0"

# Define the temporary directory for cloning the repository
TMP_DIR="/tmp/your_project_directory"

# Define the installation directory
INSTALL_DIR="$HOME/.git-secret-protector"

# Step 1: Clone the repository into the /tmp directory
echo "Cloning the repository into /tmp directory..."
git clone --branch $TAG $REPO_URL $TMP_DIR

# Navigate to the project directory
cd $TMP_DIR

# Step 2: Install Poetry if not already installed
if ! command -v poetry &> /dev/null
then
    echo "Poetry could not be found, installing..."
    curl -sSL https://install.python-poetry.org | python3 -
else
    echo "Poetry is already installed."
fi

# Initialize Poetry and install dependencies
echo "Installing dependencies using Poetry..."
poetry install

# Step 3: Build the executable using PyInstaller
echo "Building the executable..."
poetry run pyinstaller --onefile ./src/git_secret_protector/main.py

# Step 4: Create the installation directory if it doesn't exist
mkdir -p $INSTALL_DIR

# Move the executable to the custom installation directory
echo "Installing the executable to $INSTALL_DIR..."
cp dist/your_script $INSTALL_DIR/

# Clean up the temporary files
echo "Cleaning up..."
rm -rf $TMP_DIR

# Print instructions to add the executable to PATH via .bashrc
echo "Installation completed successfully!"
echo "Add the following line to your .bashrc to use the tool from any terminal:"
echo 'export PATH="$HOME/.git-secret-protector:$PATH"'

# Optionally, automatically add the line to .bashrc if it doesn't already exist
if ! grep -q ".git-secret-protector" ~/.bashrc; then
    echo 'export PATH="$HOME/.git-secret-protector:$PATH"' >> ~/.bashrc
    echo "PATH updated in .bashrc, please restart your terminal or source .bashrc"
fi
