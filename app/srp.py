from __future__ import annotations

from hashlib import sha256
import os
import base64
import hmac
from sqlalchemy.orm import Session
from app.models import SRPSession, User

class SRPHelper:
    """
    SRP-6a helper methods with two compatibility layers:
    - Legacy/simple flow used by local tests: 1024-bit params, hex encoding.
    - Session-based flow used by Ente endpoints below (reuses same params).
    """

    # SRP parameters
    # 1024-bit (kept for local tests)
    SRP_N_1024 = (1 << 1024) - 109  # simple deterministic prime for tests
    SRP_G_1024 = 2
    SRP_KEY_LENGTH_1024 = 128  # bytes for 1024-bit N

    # 2048-bit (closer to Ente/RFC 5054 typical choice). Using a constructed prime for illustration.
    # In production, use RFC 5054 2048-bit safe prime. Here, define a deterministic large odd number
    # that behaves as modulus for math without external deps.
    SRP_N_2048 = (1 << 2048) - 213
    SRP_G_2048 = 2
    SRP_KEY_LENGTH_2048 = 256  # bytes for 2048-bit N

    SRP_SALT_LENGTH = 16  # bytes

    # Backwards-compatible aliases for local tests expecting these names
    SRP_N = SRP_N_1024
    SRP_G = SRP_G_1024
    SRP_KEY_LENGTH = SRP_KEY_LENGTH_1024

    @staticmethod
    def generate_salt() -> str:
        """Generate a random 16-byte salt and return as hex string."""
        salt_bytes = os.urandom(SRPHelper.SRP_SALT_LENGTH)
        return salt_bytes.hex()

    @staticmethod  
    def generate_verifier(srp_user_id: str, password: str, salt: str) -> str:
        """Generate SRP verifier (hex) using simple SRP-6a x = H(salt | H(I:password))."""
        x = SRPHelper._calculate_x(srp_user_id, password, salt)
        # For generator, default to 1024-bit test params for local tests
        v = pow(SRPHelper.SRP_G_1024, x, SRPHelper.SRP_N_1024)
        v_bytes = v.to_bytes(SRPHelper.SRP_KEY_LENGTH_1024, byteorder="big")
        return v_bytes.hex()

    @staticmethod
    def _calculate_x(srp_user_id: str, password: str, salt: str) -> int:
        """Calculate SRP private key x from identity, password and hex salt."""
        salt_bytes = bytes.fromhex(salt)
        inner = sha256(f"{srp_user_id}:{password}".encode("utf-8")).digest()
        x_hash = sha256(salt_bytes + inner).digest()
        return int.from_bytes(x_hash, byteorder="big")

    @staticmethod
    def _calculate_k(N: int, g: int, key_len: int) -> int:
        """Calculate multiplier parameter k = H(N || g) for given params"""
        N_bytes = N.to_bytes(key_len, byteorder='big')
        g_bytes = g.to_bytes(key_len, byteorder='big')
        k_hash = sha256(N_bytes + g_bytes).digest()
        return int.from_bytes(k_hash, byteorder='big')

    @staticmethod
    def _calculate_u(A: int, B: int, key_len: int) -> int:
        """Calculate scrambling parameter u = H(A || B)"""
        A_bytes = A.to_bytes(key_len, byteorder='big')
        B_bytes = B.to_bytes(key_len, byteorder='big')
        u_hash = sha256(A_bytes + B_bytes).digest()
        return int.from_bytes(u_hash, byteorder='big')

    @staticmethod
    def _parse_hex_or_b64_to_bytes(value: str) -> bytes | None:
        """Try hex first then base64 for incoming verifier/salt strings."""
        if value is None:
            return None
        s = str(value)
        try:
            return bytes.fromhex(s)
        except Exception:
            pass
        try:
            return base64.b64decode(s, validate=False)
        except Exception:
            return None

    @classmethod
    def _select_params_from_vbytes(cls, v_bytes: bytes | None):
        """Choose N, g, key_len based on verifier byte length; default to 1024.
        128 bytes => 1024-bit; 256 bytes => 2048-bit.
        """
        if v_bytes is None:
            return cls.SRP_N_1024, cls.SRP_G_1024, cls.SRP_KEY_LENGTH_1024
        if len(v_bytes) >= cls.SRP_KEY_LENGTH_2048:
            return cls.SRP_N_2048, cls.SRP_G_2048, cls.SRP_KEY_LENGTH_2048
        return cls.SRP_N_1024, cls.SRP_G_1024, cls.SRP_KEY_LENGTH_1024

    # ---- Simple, stateless helpers used by legacy tests
    @staticmethod
    def create_server_challenge(srp_user_id: str, client_A_hex: str, verifier_hex: str, salt_hex: str) -> dict:
        """Create challenge response using provided hex A, v, salt. Returns hex B and salt."""
        _ = int(client_A_hex, 16)
        # Use 1024-bit test params for legacy/simple flow
        try:
            v = int(verifier_hex, 16)
        except Exception:
            v = 0
        b = int.from_bytes(os.urandom(32), byteorder="big")
        k = SRPHelper._calculate_k(SRPHelper.SRP_N_1024, SRPHelper.SRP_G_1024, SRPHelper.SRP_KEY_LENGTH_1024)
        B = (k * v + pow(SRPHelper.SRP_G_1024, b, SRPHelper.SRP_N_1024)) % SRPHelper.SRP_N_1024
        return {
            "salt": salt_hex,
            "server_B": B.to_bytes(SRPHelper.SRP_KEY_LENGTH_1024, byteorder="big").hex(),
        }

    @staticmethod
    def verify_client_auth(srp_user_id: str, client_A_hex: str, client_M1: str, server_B_hex: str, verifier_hex: str, salt_hex: str) -> dict:
        """
        Placeholder verifier for tests (usually patched). Returns failure by default.
        """
        return {"verified": False, "server_proof": ""}

    @classmethod
    def create_srp_session(
        cls, 
        db: Session, 
        srp_user_id: str, 
        client_A: str
    ) -> tuple[str, str]:
        """
        Create a new SRP session for authentication
        Returns (session_id, server_B)
        """
        import uuid
        import datetime as dt
        
        # Generate session ID
        session_id = str(uuid.uuid4())

        # Parse client A (validation - ensure it's not zero). Expect base64 here.
        A_int = int(base64.b64decode(client_A).hex(), 16)
        if A_int == 0:
            raise ValueError("Invalid client A value")
        
        # Generate server private key b
        b = int.from_bytes(os.urandom(32), byteorder='big')
        
        # Get user's verifier from database (required for proper B)
        user = (
            db.query(User)
            .filter((User.srp_user_id == srp_user_id) | (User.email == srp_user_id))
            .first()
        )
        verifier_hex = getattr(user, "srp_verifier", None) if user else None
        if not verifier_hex:
            # If no verifier exists yet (e.g., setup flow), use v=0 so B = g^b mod N
            v = 0
        else:
            v_bytes = cls._parse_hex_or_b64_to_bytes(str(verifier_hex))
            if v_bytes is None or len(v_bytes) == 0:
                v = 0
            else:
                v = int.from_bytes(v_bytes, byteorder='big')
        
        # Select params based on verifier size (or default 1024 when v==0)
        if v == 0:
            N, g, key_len = cls.SRP_N_1024, cls.SRP_G_1024, cls.SRP_KEY_LENGTH_1024
        else:
            v_len_bytes = (v.bit_length() + 7) // 8
            N, g, key_len = cls._select_params_from_vbytes(v_len_bytes.to_bytes(max(1, v_len_bytes), 'big'))

        # Calculate k and B
        k = cls._calculate_k(N, g, key_len)
        B = (k * v + pow(g, b, N)) % N
        
        # Store session
        session = SRPSession(
            session_id=session_id,
            srp_user_id=srp_user_id,
            srp_a=client_A,
            srp_b=base64.b64encode(B.to_bytes(key_len, byteorder='big')).decode('ascii'),
            srp_b_private=base64.b64encode(b.to_bytes(32, byteorder='big')).decode('ascii'),
            expires_at=dt.datetime.utcnow() + dt.timedelta(minutes=5)
        )
        
        db.add(session)
        db.commit()

        server_B = base64.b64encode(B.to_bytes(key_len, byteorder='big')).decode('ascii')
        return session_id, server_B

    @classmethod
    def verify_srp_session(
        cls,
        db: Session,
        session_id: str,
        srp_user_id: str,
        client_M1: str
    ) -> tuple[bool, str]:
        """
        Verify SRP session and client proof M1
        Returns (verified, server_M2)
        """
        import datetime as dt
        
        # Get session
        session = db.query(SRPSession).filter(
            SRPSession.session_id == session_id,
            SRPSession.srp_user_id == srp_user_id,
            SRPSession.expires_at > dt.datetime.utcnow()
        ).first()
        
        if not session:
            return False, ""
        
        # Parse session data
        A_bytes = base64.b64decode(str(session.srp_a))
        B_bytes = base64.b64decode(str(session.srp_b))
        A = int(A_bytes.hex(), 16)  
        B = int(B_bytes.hex(), 16)
        b = int(base64.b64decode(str(session.srp_b_private)).hex(), 16)
        
        # Get user verifier and salt
        user = (
            db.query(User)
            .filter((User.srp_user_id == srp_user_id) | (User.email == srp_user_id))
            .first()
        )
        if not user or not getattr(user, 'srp_verifier', None) or not getattr(user, 'srp_salt', None):
            return False, ""
        v_bytes = cls._parse_hex_or_b64_to_bytes(str(user.srp_verifier))
        if not v_bytes:
            return False, ""
        v = int.from_bytes(v_bytes, byteorder='big')
        
        # Calculate scrambling parameter u
        # Select SRP params by verifier length
        N, g, key_len = cls._select_params_from_vbytes(v_bytes)

        u = cls._calculate_u(A, B, key_len)
        
        # Calculate shared secret S = (A * v^u)^b mod N
        S = pow((A * pow(v, u, N)) % N, b, N)
        
        # Calculate session key K = H(S)
        S_bytes = S.to_bytes(key_len, byteorder='big')
        K = sha256(S_bytes).digest()
        
        # Calculate expected M1 = H(H(N) XOR H(g) | H(I) | salt | A | B | K)
        N_hash = sha256(N.to_bytes(key_len, byteorder='big')).digest()
        g_hash = sha256(g.to_bytes(key_len, byteorder='big')).digest()
        ng_xor = bytes(a ^ b for a, b in zip(N_hash, g_hash))
        
        I_hash = sha256(srp_user_id.encode('utf-8')).digest()

        # For salt, use the stored salt from user (hex decoded)
        salt_bytes = cls._parse_hex_or_b64_to_bytes(str(user.srp_salt))
        if not salt_bytes:
            return False, ""
        
        A_bytes = A.to_bytes(key_len, byteorder='big')
        B_bytes = B.to_bytes(key_len, byteorder='big')
        
        M1_input = ng_xor + I_hash + salt_bytes + A_bytes + B_bytes + K
        expected_M1 = sha256(M1_input).digest()
        expected_M1_b64 = base64.b64encode(expected_M1).decode('ascii')
        
        # Verify M1
        verified = hmac.compare_digest(expected_M1_b64, client_M1)
        
        server_M2 = ""
        if verified:
            # Calculate M2 = H(A | M1 | K)  
            M2_input = A_bytes + expected_M1 + K
            M2 = sha256(M2_input).digest()
            server_M2 = base64.b64encode(M2).decode('ascii')
            
            # Mark session as verified
            db.query(SRPSession).filter(
                SRPSession.session_id == session_id
            ).update({SRPSession.is_verified: True})
            db.commit()
        
        return verified, server_M2
