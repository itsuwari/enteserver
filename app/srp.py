from __future__ import annotations

from hashlib import sha256
import os
import base64
import binascii
import hmac

class SRPHelper:
    """SRP6a utilities for Ente-compatible authentication"""

    # SRP-6a parameters (compatible with Ente)
    SRP_N = int("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3", 16)  # 1024-bit prime
    SRP_G = 2
    SRP_SALT_LENGTH = 16
    """SRP6a utilities for Ente-compatible authentication"""

    @staticmethod
    def generate_salt() -> str:
        """Generate a random 16-byte salt for SRP"""
        salt_bytes = os.urandom(SRPHelper.SRP_SALT_LENGTH)
        return binascii.hexlify(salt_bytes).decode('ascii')

    @staticmethod
    def _calculate_x(username: str, password: str, salt: str) -> int:
        """Calculate SRP x parameter from credentials and salt"""
        salt_bytes = binascii.unhexlify(salt)
        username_password = f"{username}:{password}".encode('utf-8')
        username_password_hash = sha256(username_password).digest()

        x_hash = hmac.new(salt_bytes, username_password_hash, sha256).digest()
        return int.from_bytes(x_hash, byteorder='big')

    @staticmethod
    def generate_verifier(username: str, password: str, salt: str) -> str:
        """Generate SRP verifier for user registration"""
        x = SRPHelper._calculate_x(username, password, salt)
        v = pow(SRPHelper.SRP_G, x, SRPHelper.SRP_N)

        # Return hexadecimal string for storage
        return hex(v)[2:]  # Remove '0x' prefix

    @staticmethod
    def _calculate_A(generator: int, private_key: int) -> int:
        """Calculate client's public key A"""
        return pow(generator, private_key, SRPHelper.SRP_N)

    @staticmethod
    def _calculate_B(generator: int, verifier: int, k: int, private_key: int) -> int:
        """Calculate server's public key B"""
        return (k * verifier + pow(generator, private_key, SRPHelper.SRP_N)) % SRPHelper.SRP_N

    @staticmethod
    def _calculate_u(client_A: int, server_B: int) -> int:
        """Calculate u parameter: SHA256(A || B)"""
        a_bytes = client_A.to_bytes((client_A.bit_length() + 7) // 8, byteorder='big')
        b_bytes = server_B.to_bytes((server_B.bit_length() + 7) // 8, byteorder='big')
        u_hash = sha256(a_bytes + b_bytes).digest()
        return int.from_bytes(u_hash, byteorder='big')

    @staticmethod
    def create_server_challenge(username: str, client_A: str, verifier_hex: str, salt: str):
        """
        Server creates challenge for SRP handshake

        Returns:
            dict: Contains server_B, server_proof, and salt
        """
        # Parse inputs
        client_A_int = int(client_A, 16)
        verifier_int = int(verifier_hex, 16)
        salt_bytes = binascii.unhexlify(salt)

        # Generate server private key
        server_b = int.from_bytes(os.urandom(32), byteorder='big')

        # Calculate k parameter: SHA256(N || pad(g))
        N_bytes = SRPHelper.SRP_N.to_bytes(128, byteorder='big')  # 1024 bits = 128 bytes
        g_bytes = SRPHelper.SRP_G.to_bytes(1, byteorder='big')
        if len(g_bytes) < len(N_bytes):
            g_bytes = b'\x00' * (len(N_bytes) - len(g_bytes)) + g_bytes
        k = int.from_bytes(sha256(N_bytes + g_bytes).digest(), byteorder='big')

        # Calculate server public key B
        server_B_int = SRPHelper._calculate_B(SRPHelper.SRP_G, verifier_int, k, server_b)

        # Calculate u parameter
        u_int = SRPHelper._calculate_u(client_A_int, server_B_int)

        # Calculate server proof M2 = SHA256(A || M1 || K)
        # First we need shared secret K, then M1 (client proof), then M2
        # This is simplified for initial implementation

        return {
            'server_B': hex(server_B_int)[2:].zfill(64),  # Ensure consistent length
            'salt': salt,
            'server_proof': '',  # Will be calculated after client proof verification
        }

    @staticmethod
    def verify_client_auth(username: str, client_A: str, client_proof: str, server_B: str, verifier_hex: str, salt: str):
        """
        Verify client's authentication proof

        Returns:
            dict: Contains verification status and session proof M2
        """
        # Parse inputs
        client_A_int = int(client_A, 16)
        server_B_int = int(server_B, 16)
        verifier_int = int(verifier_hex, 16)
        salt_bytes = binascii.unhexlify(salt)

        # Generate server private key (should be stored from challenge phase)
        server_b = int.from_bytes(os.urandom(32), byteorder='big')  # FIXME: store/restore this

        # Calculate k parameter
        N_bytes = SRPHelper.SRP_N.to_bytes(128, byteorder='big')
        g_bytes = SRPHelper.SRP_G.to_bytes(1, byteorder='big')
        if len(g_bytes) < len(N_bytes):
            g_bytes = b'\x00' * (len(N_bytes) - len(g_bytes)) + g_bytes
        k = int.from_bytes(sha256(N_bytes + g_bytes).digest(), byteorder='big')

        # Calculate u parameter
        u_int = SRPHelper._calculate_u(client_A_int, server_B_int)

        # Calculate shared secret S
        # S = (A * v^u) ^ b mod N
        base = (client_A_int * pow(verifier_int, u_int, SRPHelper.SRP_N)) % SRPHelper.SRP_N
        shared_secret_int = pow(base, server_b, SRPHelper.SRP_N)

        # Calculate session key K = SHA256(S)
        K = sha256(shared_secret_int.to_bytes(128, byteorder='big')).digest()

        # Calculate client proof M1 = SHA256( SHA256(N) XOR SHA256(g) | SHA256(username) | salt | A | B | K )
        # This follows the SRP-6a specification

        # Create M1
        N_hash = sha256(N_bytes).digest()
        g_padded = SRPHelper.SRP_G.to_bytes(128, byteorder='big')  # Pad to same length as N
        g_hash = sha256(g_padded).digest()

        # XOR N_hash and g_hash
        xor_result = bytes(a ^ b for a, b in zip(N_hash, g_hash))

        username_hash = sha256(username.encode('utf-8')).digest()

        A_bytes = client_A_int.to_bytes(128, byteorder='big')
        B_bytes = server_B_int.to_bytes(128, byteorder='big')

        M1_base = xor_result + username_hash + salt_bytes + A_bytes + B_bytes + K
        expected_M1 = sha256(M1_base).hexdigest()

        # Check if client's proof matches expected
        proof_matches = hmac.compare_digest(expected_M1, client_proof)

        server_proof = ""
        if proof_matches:
            # Generate server proof M2 = SHA256(A | M1 | K)
            M2_base = A_bytes + M1_base + K
            server_proof = sha256(M2_base).hexdigest()

        return {
            'verified': proof_matches,
            'server_proof': server_proof
        }
