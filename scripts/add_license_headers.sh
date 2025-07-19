#!/bin/bash
# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT

# Script to add license headers to all source files

LICENSE_ZIG="// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT"

LICENSE_SH="# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT"

LICENSE_ASM="// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT"

LICENSE_LD="/* Copyright 2025 arancormonk
 * SPDX-License-Identifier: MIT */"

# Function to check if file already has license header
has_license_header() {
    local file="$1"
    local pattern="$2"
    
    # Check if the pattern exists in the first 5 lines
    head -n 5 "$file" | grep -q "SPDX-License-Identifier: MIT"
}

# Function to add license header to a file
add_license_header() {
    local file="$1"
    local header="$2"
    
    # Create a temporary file
    local tmp_file=$(mktemp)
    
    # Write the header and original content to temp file
    echo "$header" > "$tmp_file"
    echo "" >> "$tmp_file"
    cat "$file" >> "$tmp_file"
    
    # Replace the original file
    mv "$tmp_file" "$file"
    
    echo "Added license header to: $file"
}

# Process all Zig files
echo "Processing Zig files..."
find . -name "*.zig" -type f | while read -r file; do
    if ! has_license_header "$file"; then
        add_license_header "$file" "$LICENSE_ZIG"
    else
        echo "License header already present in: $file"
    fi
done

# Process all shell scripts
echo -e "Processing shell scripts..."
find . -name "*.sh" -type f | while read -r file; do
    if ! has_license_header "$file"; then
        add_license_header "$file" "$LICENSE_SH"
    else
        echo "License header already present in: $file"
    fi
done

# Process all assembly files
echo -e "Processing assembly files..."
find . -name "*.S" -type f | while read -r file; do
    if ! has_license_header "$file"; then
        add_license_header "$file" "$LICENSE_ASM"
    else
        echo "License header already present in: $file"
    fi
done

# Process all linker script files
echo -e "Processing linker script files..."
find . -name "*.ld" -type f | while read -r file; do
    if ! has_license_header "$file"; then
        add_license_header "$file" "$LICENSE_LD"
    else
        echo "License header already present in: $file"
    fi
done

echo -e "Done!"