#!/usr/bin/env python3
"""
Firmware signature service for ESP32 OTA Server
Handles RSA signature generation and verification using cryptography library
"""

import os
import json
import hashlib
import base64
from datetime import datetime
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

class SignatureService:
    def __init__(self, private_key_path: str = None, public_key_path: str = None):
        """Initialize signature service with RSA key pair"""
        self.private_key = None
        self.public_key = None
        self.private_key_path = private_key_path or "/opt/esp32-ota-server/keys/private_key.pem"
        self.public_key_path = public_key_path or "/opt/esp32-ota-server/keys/public_key.pem"
        
        # Create keys directory
        os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
        
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones"""
        if os.path.exists(self.private_key_path):
            try:
                self._load_private_key(self.private_key_path)
                logger.info("RSA keys loaded successfully")
                return
            except Exception as e:
                logger.warning(f"Failed to load existing keys: {e}")
        
        logger.info("Generating new RSA key pair...")
        self._generate_key_pair()
        self._save_keys()
    
    def _generate_key_pair(self):
        """Generate a new RSA 2048-bit key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        logger.info("New RSA 2048-bit key pair generated")
    
    def _load_private_key(self, key_path: str, password: bytes = None):
        """Load private key from PEM file"""
        with open(key_path, 'rb') as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
        self.public_key = self.private_key.public_key()
    
    def _save_keys(self):
        """Save keys to PEM files"""
        # Save private key
        pem_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(self.private_key_path, 'wb') as key_file:
            key_file.write(pem_private)
        
        # Save public key
        pem_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(self.public_key_path, 'wb') as key_file:
            key_file.write(pem_public)
        
        logger.info(f"Keys saved: {self.private_key_path}, {self.public_key_path}")
    
    def get_public_key_pem(self) -> str:
        """Get public key as PEM string for ESP32 embedding"""
        pem_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_public.decode('utf-8')
    
    def calculate_sha256(self, data: bytes) -> bytes:
        """Calculate SHA256 hash of data"""
        return hashlib.sha256(data).digest()
    
    def sign_firmware(self, firmware_data: bytes) -> Tuple[bytes, bytes]:
        """
        Sign firmware data using RSA private key with PKCS#1 v1.5 padding
        Compatible with WolfSSL implementation on ESP32
        
        Returns:
            Tuple of (hash, signature)
        """
        if not self.private_key:
            raise RuntimeError("Private key not loaded")
        
        # Calculate SHA256 hash
        hash_bytes = self.calculate_sha256(firmware_data)
        
        # Sign using PKCS#1 v1.5 padding (WolfSSL compatible)
        signature = self.private_key.sign(
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return hash_bytes, signature
    
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify signature (for testing)"""
        try:
            hash_bytes = self.calculate_sha256(data)
            
            self.public_key.verify(
                signature,
                hash_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def create_signature_data(self, firmware_path: str, version: str) -> Dict:
        """
        Create signature data structure for firmware file
        
        Args:
            firmware_path: Path to firmware binary file
            version: Firmware version string
            
        Returns:
            Dictionary containing signature information
        """
        try:
            # Read firmware file
            with open(firmware_path, 'rb') as f:
                firmware_data = f.read()
            
            logger.info(f"Creating signature for firmware: {firmware_path}")
            logger.info(f"Firmware size: {len(firmware_data)} bytes")
            logger.info(f"Version: {version}")
            
            # Generate signature
            hash_bytes, signature = self.sign_firmware(firmware_data)
            
            # Create signature data structure
            signature_data = {
                "signature": base64.b64encode(signature).decode('utf-8'),
                "hash": base64.b64encode(hash_bytes).decode('utf-8'),
                "firmware_size": len(firmware_data),
                "version": version,
                "timestamp": int(datetime.now().timestamp()),
                "algorithm": "RSA-PKCS1v15-SHA256",
                "created_at": datetime.now().isoformat()
            }
            
            # Verify signature for testing
            if self.verify_signature(firmware_data, signature):
                logger.info("✓ Signature verification successful")
            else:
                logger.error("✗ Signature verification failed")
                return None
            
            return signature_data
            
        except Exception as e:
            logger.error(f"Error creating firmware signature: {e}")
            return None
    
    def save_signature_file(self, signature_data: Dict, firmware_id: int) -> str:
        """Save signature data to file"""
        signatures_dir = "/opt/esp32-ota-server/signatures"
        os.makedirs(signatures_dir, exist_ok=True)
        
        signature_file = os.path.join(signatures_dir, f"firmware_{firmware_id}.sig.json")
        
        with open(signature_file, 'w') as f:
            json.dump(signature_data, f, indent=2)
        
        logger.info(f"Signature data saved to: {signature_file}")
        return signature_file
    
    def load_signature_file(self, firmware_id: int) -> Optional[Dict]:
        """Load signature data from file"""
        signatures_dir = "/opt/esp32-ota-server/signatures"
        signature_file = os.path.join(signatures_dir, f"firmware_{firmware_id}.sig.json")
        
        if not os.path.exists(signature_file):
            return None
        
        try:
            with open(signature_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading signature file: {e}")
            return None

# Global signature service instance
_signature_service = None

def get_signature_service() -> SignatureService:
    """Get singleton signature service instance"""
    global _signature_service
    if _signature_service is None:
        _signature_service = SignatureService()
    return _signature_service
