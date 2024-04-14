
#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Check if Rust is installed, install if not (optional step)
if ! command -v rustc &>/dev/null; then
    echo "Rust is not installed. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    -s -- -y
    source $HOME/.cargo/env
else
    echo "Rust is installed."
fi

# Navigate to your Rust project directory if not running the script from there
# cd /path/to/your/project

# Build the Rust project
echo "Building the Rust project..."
cargo build --release

# Run the application
echo "Running the application..."
chmod +x ./target/release/code-challenge-2024-lla-dane
./target/release/code-challenge-2024-lla-dane