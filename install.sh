
#!/bin/bash

set -e

# Install Homebrew and prerequisites if on macOS
if [ "$(uname)" == "Darwin" ]; then
  # Check if Homebrew is installed
  if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add Homebrew to PATH (adjust based on shell, assuming zsh as per user info)
    echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zshrc
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi
  # Install python and git if not presesournt
  if ! command -v python3 &> /dev/null || ! command -v git &> /dev/null; then
    brew install python git
  fi
fi

# Install system dependencies if on Linux
if [ "$(uname)" == "Linux" ]; then
  sudo apt-get update
  sudo apt-get install -y libusb-1.0-0-dev libudev-dev
fi

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies from requirements.txt
pip install -r requirements.txt

# Install hidapi from local directory
git clone --recursive https://github.com/AnchorWatch/cython-hidapi.git
cd cython-hidapi
python setup.py build
python setup.py install
cd ..



echo "Installation complete. To run the script, activate the virtual environment with 'source .venv/bin/activate' and then run 'python recover.py'."

