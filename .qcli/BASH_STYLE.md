# s2n-tls Bash Scripting Style Guide

This document outlines the bash scripting conventions and style guidelines for the s2n-tls project.

## General Structure

### File Header

All bash scripts should include the standard Apache 2.0 license header:

```bash
#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
```

### Shebang Line

- Use `#!/usr/bin/env bash` for better portability across systems
- For simple scripts, `#!/bin/bash` is also acceptable

### Error Handling

- Include `set -e` near the top of scripts to exit on any error
- Consider using `set -u` to exit on undefined variables
- For more complex scripts, consider `set -o pipefail` to catch errors in pipelines

```bash
set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit if any command in a pipeline fails
```

## Coding Style

### Indentation and Spacing

- Use 4 spaces for indentation
- No trailing whitespace
- Use blank lines to separate logical sections of code

### Variable Naming

- Use lowercase for variable names
- Use underscores to separate words
- Use uppercase for constants or environment variables

```bash
local my_variable="value"
readonly MAX_RETRIES=5
```

### Quoting

- Always quote variables: `"$variable"` not `$variable`
- Use double quotes for strings with variables
- Use single quotes for literal strings

```bash
echo "The value is: $value"
echo 'This is a literal string'
```

### Functions

- Define functions with the `function` keyword for clarity
- Use lowercase names with underscores
- Include a brief comment describing the function's purpose

```bash
function install_dependency() {
    # Install the specified dependency
    local package_name="$1"
    apt-get install -y "$package_name"
}
```

### Command Substitution

- Use `$(command)` instead of backticks
- Quote the result when storing in variables

```bash
local files="$(find . -name "*.sh")"
```

### Conditionals

- Use spaces after brackets in conditionals
- Use double brackets for string comparisons
- Use double parentheses for arithmetic operations

```bash
if [[ "$string" == "value" ]]; then
    echo "Strings match"
fi

if (( number > 0 )); then
    echo "Positive number"
fi
```

### Error Messages and Logging

- Print error messages to stderr
- Use descriptive error messages
- Consider using different output formats for different message types

```bash
function log_error() {
    echo -e "\e[1;31mERROR:\e[0m $*" >&2
}

function log_info() {
    echo -e "\e[1;34mINFO:\e[0m $*"
}
```

## Best Practices

### Input Validation

- Validate command-line arguments
- Check for required environment variables
- Provide usage information when invalid input is detected

```bash
function usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -f, --file FILE    Specify input file"
    exit 1
}

if [[ $# -eq 0 ]]; then
    usage
fi
```

### Temporary Files

- Use `mktemp` to create temporary files
- Clean up temporary files with trap

```bash
temp_file=$(mktemp)
trap 'rm -f "$temp_file"' EXIT
```

### Command Line Parsing

- For simple scripts, use positional parameters
- For more complex scripts, use getopts or a manual parsing loop

```bash
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            file="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done
```

### Platform Detection

- Use environment variables or commands to detect the platform
- Handle different platforms with case statements

```bash
case "$(uname -s)" in
    Linux*)
        install_linux_dependencies
        ;;
    Darwin*)
        install_mac_dependencies
        ;;
    *)
        echo "Unsupported platform"
        exit 1
        ;;
esac
```

## Testing and Linting

### ShellCheck

The s2n-tls project uses ShellCheck for static analysis of shell scripts. Install it using:

```bash
# On Ubuntu/Debian
apt-get install shellcheck

# On macOS
brew install shellcheck
```

Run ShellCheck on your scripts:

```bash
shellcheck your_script.sh
```

### Common ShellCheck Rules to Follow

- SC2086: Double quote to prevent globbing and word splitting
- SC2046: Quote this to prevent word splitting
- SC2006: Use $(...) notation instead of legacy backticks
- SC2034: Variable appears unused
- SC2164: Use 'cd ... || exit' or 'cd ... || return' in case cd fails

## Example Script

```bash
#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

set -e

# Global constants
readonly MAX_RETRIES=3
readonly TEMP_DIR=$(mktemp -d)

# Clean up on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

function log_info() {
    echo -e "\e[1;34mINFO:\e[0m $*"
}

function log_error() {
    echo -e "\e[1;31mERROR:\e[0m $*" >&2
}

function usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -p, --package PACKAGE    Specify package to install"
    echo "  -h, --help               Show this help message"
    exit 1
}

function install_package() {
    local package_name="$1"
    local attempt=1
    
    while (( attempt <= MAX_RETRIES )); do
        log_info "Installing $package_name (attempt $attempt/$MAX_RETRIES)"
        
        if apt-get install -y "$package_name"; then
            log_info "Successfully installed $package_name"
            return 0
        fi
        
        log_error "Failed to install $package_name"
        (( attempt++ ))
        sleep 2
    done
    
    log_error "Failed to install $package_name after $MAX_RETRIES attempts"
    return 1
}

# Parse command line arguments
package=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--package)
            package="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate input
if [[ -z "$package" ]]; then
    log_error "Package name is required"
    usage
fi

# Main execution
log_info "Starting installation process"
install_package "$package"
log_info "Installation complete"
```
