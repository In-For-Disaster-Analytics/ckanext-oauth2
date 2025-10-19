# -*- coding: utf-8 -*-

"""
Tests for RS256 JWT algorithm support.

This test ensures that the cryptography library is installed and working
for asymmetric JWT algorithms like RS256, RS384, RS512, ES256, etc.
"""

import pytest
import jwt
from datetime import datetime, timedelta


class TestJWTRS256:
    """Test RS256 JWT verification"""

    def test_cryptography_installed(self):
        """Verify cryptography library is available"""
        try:
            import cryptography
            assert cryptography is not None
        except ImportError:
            pytest.fail("cryptography library not installed - required for RS256 algorithm")

    def test_rs256_algorithm_available(self):
        """Verify RS256 algorithm is available in PyJWT"""
        from jwt.algorithms import get_default_algorithms

        algorithms = get_default_algorithms()
        assert 'RS256' in algorithms, "RS256 algorithm not found in PyJWT"
        assert 'RS384' in algorithms, "RS384 algorithm not found in PyJWT"
        assert 'RS512' in algorithms, "RS512 algorithm not found in PyJWT"

    def test_rs256_jwt_encode_decode(self):
        """Test encoding and decoding a JWT with RS256"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Create JWT payload
        payload = {
            'sub': 'test_user',
            'email': 'test@example.com',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }

        # Encode with RS256
        token = jwt.encode(payload, private_pem, algorithm='RS256')

        # Decode and verify with public key
        decoded = jwt.decode(token, public_pem, algorithms=['RS256'])

        assert decoded['sub'] == 'test_user'
        assert decoded['email'] == 'test@example.com'

    def test_rs256_jwt_verification_fails_with_wrong_key(self):
        """Test that JWT verification fails with wrong public key"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Generate first RSA key pair
        private_key1 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem1 = private_key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Generate second RSA key pair (different keys)
        private_key2 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key2 = private_key2.public_key()
        public_pem2 = public_key2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Create and encode JWT with first private key
        payload = {
            'sub': 'test_user',
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, private_pem1, algorithm='RS256')

        # Try to decode with different public key - should fail
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(token, public_pem2, algorithms=['RS256'])
