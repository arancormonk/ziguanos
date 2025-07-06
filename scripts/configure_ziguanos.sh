# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT

#!/bin/bash
# Ziguanos Configuration Management Script
# This script manages the ziguanos.conf file that gets included in the EFI System Partition

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/zig-out"
CONFIG_FILE="$BUILD_DIR/ziguanos.conf"
# HMAC keys are now stored in UEFI variables, not on disk

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_usage() {
    printf "${BOLD}Ziguanos Configuration Manager${NC}\n"
    printf "\n"
    printf "Usage: %s [command] [options]\n" "$0"
    printf "\n"
    printf "${BOLD}Commands:${NC}\n"
    printf "  ${CYAN}show${NC}                     - Show current configuration\n"
    printf "  ${CYAN}kaslr-enable${NC}             - Enable KASLR\n"
    printf "  ${CYAN}kaslr-disable${NC}            - Disable KASLR\n"
    printf "  ${CYAN}security-level${NC} <level>   - Set security level (development/production/strict)\n"
    printf "  ${CYAN}set${NC} <key> <value>        - Set a specific configuration value\n"
    printf "  ${CYAN}defaults${NC}                 - Reset to default configuration\n"
    printf "  ${CYAN}edit${NC}                     - Edit configuration file directly\n"
    printf "\n"
    printf "${BOLD}Examples:${NC}\n"
    printf "  %s kaslr-disable\n" "$0"
    printf "  %s security-level development\n" "$0"
    printf "  %s set KASLRRdrandRetries 20\n" "$0"
    printf "\n"
    printf "${BOLD}Note:${NC} Changes take effect on next 'zig build test' or 'zig build run'\n"
}

create_default_config() {
    cat > "$CONFIG_FILE" << 'EOF'
# Ziguanos Configuration File
# This file is read by the UEFI bootloader from the EFI System Partition
# Changes take effect on next boot

# KASLR (Kernel Address Space Layout Randomization) Settings
KASLREnabled=enabled
KASLRRdrandRetries=20
KASLRRdseedRetries=1024
KASLREnforce=disabled

# Security Level: development, production, strict
SecurityLevel=production

# Additional KASLR Settings (for future use)
# KASLRAlign=auto
# KASLRMinEntropy=6
EOF
    printf "${GREEN}Created default configuration: %s${NC}\n" "$CONFIG_FILE"
}

show_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        printf "${YELLOW}No configuration file found.${NC}\n"
        printf "${YELLOW}Run '%s defaults' to create a default configuration.${NC}\n" "$0"
        return
    fi

    printf "${BOLD}Current Ziguanos Configuration:${NC}\n"
    printf "${CYAN}File: %s${NC}\n" "$CONFIG_FILE"
    printf "\n"
    
    # Parse and display in a nice format
    while IFS= read -r line; do
        # Skip comments and empty lines
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "${line// /}" ]]; then
            continue
        fi
        
        if [[ "$line" =~ ^[[:space:]]*([^=]+)=(.*)$ ]]; then
            key="${BASH_REMATCH[1]// /}"
            value="${BASH_REMATCH[2]// /}"
            printf "  %-20s: ${GREEN}%s${NC}\n" "$key" "$value"
        fi
    done < "$CONFIG_FILE"
}

generate_config_hmac() {
    # HMAC generation has been moved to runtime using secure UEFI variables
    # Configuration integrity is now verified using runtime-generated keys
    printf "${CYAN}Note: Configuration integrity verification uses runtime UEFI keys${NC}\n"
}

set_config_value() {
    local key="$1"
    local value="$2"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        create_default_config
    fi
    
    # Use sed to update the value if key exists, or append if it doesn't
    if grep -q "^[[:space:]]*$key=" "$CONFIG_FILE"; then
        sed -i "s/^[[:space:]]*$key=.*/$key=$value/" "$CONFIG_FILE"
        printf "${GREEN}Updated %s=%s${NC}\n" "$key" "$value"
    else
        echo "$key=$value" >> "$CONFIG_FILE"
        printf "${GREEN}Added %s=%s${NC}\n" "$key" "$value"
    fi

    generate_config_hmac
}

validate_security_level() {
    case "$1" in
        "development"|"production"|"strict")
            return 0
            ;;
        *)
            printf "${RED}Error: Invalid security level '%s'${NC}\n" "$1"
            printf "${YELLOW}Valid options: development, production, strict${NC}\n"
            return 1
            ;;
    esac
}

validate_boolean() {
    case "$1" in
        "enabled"|"disabled"|"true"|"false"|"1"|"0")
            return 0
            ;;
        *)
            printf "${RED}Error: Invalid boolean value '%s'${NC}\n" "$1"
            printf "${YELLOW}Valid options: enabled, disabled, true, false, 1, 0${NC}\n"
            return 1
            ;;
    esac
}

case "${1:-show}" in
    "show")
        show_config
        ;;
    "kaslr-enable")
        set_config_value "KASLREnabled" "enabled"
        printf "${CYAN}KASLR is now enabled. Run 'zig build test' to test.${NC}\n"
        ;;
    "kaslr-disable")
        set_config_value "KASLREnabled" "disabled"
        printf "${CYAN}KASLR is now disabled. Run 'zig build test' to test.${NC}\n"
        ;;
    "security-level")
        if [ -z "$2" ]; then
            printf "${RED}Error: Security level not specified${NC}\n"
            printf "${YELLOW}Usage: %s security-level <development|production|strict>${NC}\n" "$0"
            exit 1
        fi
        
        if validate_security_level "$2"; then
            set_config_value "SecurityLevel" "$2"
            printf "${CYAN}Security level set to '%s'. Run 'zig build test' to test.${NC}\n" "$2"
        else
            exit 1
        fi
        ;;
    "set")
        if [ -z "$2" ] || [ -z "$3" ]; then
            printf "${RED}Error: Key and value required${NC}\n"
            printf "${YELLOW}Usage: %s set <key> <value>${NC}\n" "$0"
            exit 1
        fi
        
        # Basic validation for common keys
        case "$2" in
            "KASLREnabled"|"KASLREnforce")
                if ! validate_boolean "$3"; then
                    exit 1
                fi
                ;;
            "SecurityLevel")
                if ! validate_security_level "$3"; then
                    exit 1
                fi
                ;;
            "KASLRRdrandRetries"|"KASLRRdseedRetries")
                if ! [[ "$3" =~ ^[0-9]+$ ]] || [ "$3" -lt 1 ] || [ "$3" -gt 2048 ]; then
                    printf "${RED}Error: Invalid retry count '%s'${NC}\n" "$3"
                    printf "${YELLOW}Valid range: 1-2048${NC}\n"
                    exit 1
                fi
                ;;
        esac
        
        set_config_value "$2" "$3"
        printf "${CYAN}Configuration updated. Run 'zig build test' to test.${NC}\n"
        ;;
    "defaults")
        if [ -f "$CONFIG_FILE" ]; then
            printf "${YELLOW}This will overwrite the existing configuration.${NC}\n"
            printf "${YELLOW}Continue? [y/N]:${NC} "
            read -r confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                echo "Cancelled."
                exit 0
            fi
        fi
        
        create_default_config
        printf "${CYAN}Reset to defaults. Run 'zig build test' to test.${NC}\n"
        generate_config_hmac
        ;;
    "edit")
        if [ ! -f "$CONFIG_FILE" ]; then
            create_default_config
        fi
        
        # Use the user's preferred editor
        editor="${EDITOR:-nano}"
        if command -v "$editor" >/dev/null 2>&1; then
            "$editor" "$CONFIG_FILE"
            printf "${CYAN}Configuration may have been modified. Run 'zig build test' to test.${NC}\n"
            generate_config_hmac
        else
            printf "${YELLOW}Editor '%s' not found. Try setting EDITOR environment variable.${NC}\n" "$editor"
            printf "${YELLOW}File location: %s${NC}\n" "$CONFIG_FILE"
        fi
        ;;
    "help"|"--help"|"-h")
        print_usage
        ;;
    *)
        printf "${RED}Unknown command: %s${NC}\n" "$1"
        printf "\n"
        print_usage
        exit 1
        ;;
esac