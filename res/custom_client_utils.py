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


def validate_provided_keys(public_key_b64: str, private_key_b64: str) -> bool:
    """Validate that provided keys are valid and match."""
    try:
        import nacl.signing
    except ImportError:
        print("PyNaCl is required. Install with: pip install pynacl", file=sys.stderr)
        sys.exit(1)

    try:
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
    validate_keys_parser.add_argument('--public-key', required=True, help='Base64 encoded public key')
    validate_keys_parser.add_argument('--private-key', required=True, help='Base64 encoded private key')

    # Encrypt config command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt JSON configuration')
    encrypt_parser.add_argument('--config', required=True, help='JSON configuration string')
    encrypt_parser.add_argument('--private-key', required=True, help='Base64 encoded private key')
    encrypt_parser.add_argument('--output', help='Output file for encrypted config')

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


if __name__ == '__main__':
    main()
