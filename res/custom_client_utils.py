#!/usr/bin/env python3
"""
Custom client configuration encryption utility for RustDesk.
Handles JSON validation, key generation/validation, and encryption.
"""

import os
import sys
import json
import base64
import argparse
from typing import Optional, Tuple


def validate_json_config(config_str: str) -> bool:
    """Validate that the provided string is valid JSON."""
    try:
        json.loads(config_str)
        return True
    except json.JSONDecodeError:
        return False


def format_json(json_str: str) -> str:
    """Format JSON using json.tool if valid, otherwise return as-is."""
    if validate_json_config(json_str):
        try:
            import subprocess
            import tempfile
            import os

            # Write JSON to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(json_str)
                temp_file = f.name

            try:
                # Run python -m json.tool on the temp file
                result = subprocess.run(
                    [sys.executable, '-m', 'json.tool', temp_file],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return result.stdout.strip()
                else:
                    return json_str
            finally:
                # Clean up temp file
                os.unlink(temp_file)
        except Exception:
            # If formatting fails, return original
            return json_str
    return json_str


def generate_ed25519_keypair() -> Tuple[str, str]:
    """Generate a new Ed25519 keypair and return base64 encoded keys."""
    try:
        import nacl.signing
    except ImportError:
        print("PyNaCl is required. Install with: pip install pynacl", file=sys.stderr)
        sys.exit(1)

    # Generate new keypair
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    # Encode keys to base64
    public_key_b64 = base64.b64encode(verify_key.encode()).decode('utf-8')
    private_key_b64 = base64.b64encode(signing_key.encode()).decode('utf-8')

    return public_key_b64, private_key_b64


def read_param_or_file(param: str, is_json: bool = False) -> str:
    """Read parameter value from file if it exists, otherwise return as string."""
    if os.path.isfile(param):
        try:
            with open(param, 'r') as f:
                content = f.read()
                if is_json:
                    # For JSON, remove only leading/trailing whitespace but keep internal newlines
                    return content.strip()
                else:
                    # For other params, strip all whitespace
                    return content.strip()
        except Exception as e:
            print(f"Error reading file {param}: {e}", file=sys.stderr)
            sys.exit(1)
    if is_json:
        # For JSON strings, keep as-is (don't strip)
        return param
    else:
        # For other params, strip whitespace
        return param.strip()


def validate_provided_keys(public_key_b64: str, private_key_b64: str) -> bool:
    """Validate that provided keys are valid and match."""
    try:
        import nacl.signing
    except ImportError:
        print("PyNaCl is required. Install with: pip install pynacl", file=sys.stderr)
        sys.exit(1)

    try:
        # Read keys from files if they are file paths
        public_key_b64 = read_param_or_file(public_key_b64)
        private_key_b64 = read_param_or_file(private_key_b64)

        # Decode keys
        pk_bytes = base64.b64decode(public_key_b64)
        sk_bytes = base64.b64decode(private_key_b64)

        # Create key objects
        signing_key = nacl.signing.SigningKey(sk_bytes)
        verify_key = nacl.signing.VerifyKey(pk_bytes)

        # Verify they match
        if signing_key.verify_key != verify_key:
            return False

        return True
    except Exception:
        return False


def encrypt_config(config_json: str, private_key_b64: str) -> str:
    """Encrypt JSON config using Ed25519 signing."""
    try:
        import nacl.signing
    except ImportError:
        print("PyNaCl is required. Install with: pip install pynacl", file=sys.stderr)
        sys.exit(1)

    # Read config and key from files if they are file paths
    config_json = read_param_or_file(config_json, is_json=True)
    private_key_b64 = read_param_or_file(private_key_b64)

    # Format JSON if valid before encryption
    config_json = format_json(config_json)
    if not validate_json_config(config_json):
        print("Invalid JSON configuration provided", file=sys.stderr)
        sys.exit(1)

    # Decode private key
    private_key_bytes = base64.b64decode(private_key_b64)
    signing_key = nacl.signing.SigningKey(private_key_bytes)

    # Serialize JSON to bytes
    json_bytes = config_json.encode('utf-8')

    # Sign the JSON
    signed = signing_key.sign(json_bytes)

    # Encode the signed data to base64
    encrypted_config = base64.b64encode(signed).decode('utf-8')

    return encrypted_config


def decrypt_config(encrypted_config: str, public_key_b64: str) -> str:
    """Decrypt JSON config using Ed25519 signature verification."""
    try:
        import nacl.signing
    except ImportError:
        print("PyNaCl is required. Install with: pip install pynacl", file=sys.stderr)
        sys.exit(1)

    # Read encrypted config and key from files if they are file paths
    encrypted_config = read_param_or_file(encrypted_config)
    public_key_b64 = read_param_or_file(public_key_b64)

    try:
        # Decode the encrypted config from base64
        encrypted_bytes = base64.b64decode(encrypted_config)

        # Decode public key
        public_key_bytes = base64.b64decode(public_key_b64)
        verify_key = nacl.signing.VerifyKey(public_key_bytes)

        # Verify and extract the original JSON
        json_bytes = verify_key.verify(encrypted_bytes)

        # Decode back to string
        config_json = json_bytes.decode('utf-8')

        # Format JSON if valid
        config_json = format_json(config_json)
        if not validate_json_config(config_json):
            print("Decrypted data is not valid JSON", file=sys.stderr)
            sys.exit(1)

        return config_json

    except Exception as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Custom client configuration utility')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Validate JSON command
    validate_parser = subparsers.add_parser('validate-json', help='Validate JSON configuration')
    validate_parser.add_argument('--config', required=True, help='JSON configuration string')

    # Generate keys command
    gen_keys_parser = subparsers.add_parser('generate-keys', help='Generate new Ed25519 keypair')

    # Validate keys command
    validate_keys_parser = subparsers.add_parser('validate-keys', help='Validate provided keypair')
    validate_keys_parser.add_argument('--public-key', required=True, help='Base64 encoded public key or path to file containing it')
    validate_keys_parser.add_argument('--private-key', required=True, help='Base64 encoded private key or path to file containing it')

    # Encrypt config command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt JSON configuration')
    encrypt_parser.add_argument('--config', required=True, help='JSON configuration string or path to file containing it')
    encrypt_parser.add_argument('--private-key', required=True, help='Base64 encoded private key or path to file containing it')
    encrypt_parser.add_argument('--output', help='Output file for encrypted config')

    # Decrypt config command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt JSON configuration')
    decrypt_parser.add_argument('--config', required=True, help='Base64 encoded encrypted configuration or path to file containing it')
    decrypt_parser.add_argument('--public-key', required=True, help='Base64 encoded public key or path to file containing it')
    decrypt_parser.add_argument('--output', help='Output file for decrypted JSON')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'validate-json':
        if validate_json_config(args.config):
            print("JSON validation passed")
            sys.exit(0)
        else:
            print("JSON validation failed", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'generate-keys':
        public_key, private_key = generate_ed25519_keypair()

        # Also save to files for artifacts
        with open('custom_client_public_key.txt', 'w') as f:
            f.write(public_key)
        with open('custom_client_private_key.txt', 'w') as f:
            f.write(private_key)
        print("Keys saved to files")

    elif args.command == 'validate-keys':
        if validate_provided_keys(args.public_key, args.private_key):
            print("Keys validation passed")
            sys.exit(0)
        else:
            print("Keys validation failed", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'encrypt':
        encrypted = encrypt_config(args.config, args.private_key)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(encrypted)
            print(f"Encrypted config saved to {args.output}")
        else:
            print(encrypted)

    elif args.command == 'decrypt':
        decrypted = decrypt_config(args.config, args.public_key)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(decrypted)
            print(f"Decrypted config saved to {args.output}")
        else:
            print(decrypted)


if __name__ == '__main__':
    main()
