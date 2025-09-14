#!/usr/bin/env python3

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Request, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import aiofiles
import hashlib
import os
import json
from datetime import datetime
from typing import Optional
import logging

from signature_service import get_signature_service

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ESP32 OTA Update Server", 
    version="2.0.0",
    description="Secure ESP32 firmware distribution with WolfSSL compatible RSA signatures"
)

security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FIRMWARE_DIR = "/opt/esp32-ota-server/firmware"
UPLOAD_DIR = "/opt/esp32-ota-server/uploads"
API_KEY = "124JWK!weqCT1cWJm/C"

os.makedirs(FIRMWARE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

FIRMWARE_DB = "/opt/esp32-ota-server/firmware.json"

def load_firmware_db():
    try:
        with open(FIRMWARE_DB, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"firmwares": []}

def save_firmware_db(data):
    with open(FIRMWARE_DB, 'w') as f:
        json.dump(data, f, indent=2)

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials

def calculate_file_hash(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

@app.on_event("startup")
async def startup_event():
    logger.info("Starting ESP32 OTA Server with Signature Verification...")
    signature_service = get_signature_service()
    logger.info("Signature service initialized")
    
    public_key_pem = signature_service.get_public_key_pem()
    logger.info("Public key for ESP32 embedding:")
    logger.info("-" * 50)
    for line in public_key_pem.split('\n'):
        if line.strip():
            logger.info(line)
    logger.info("-" * 50)

@app.get("/")
async def root():
    return {
        "message": "ESP32 OTA Update Server",
        "status": "running",
        "version": "2.0.0",
        "features": ["RSA signature verification", "WolfSSL compatibility"]
    }

@app.get("/api/health")
async def health_check():
    signature_service = get_signature_service()
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "firmware_count": len(load_firmware_db()["firmwares"]),
        "signature_service": "active"
    }

@app.get("/api/public-key")
async def get_public_key():
    signature_service = get_signature_service()
    return {
        "public_key_pem": signature_service.get_public_key_pem(),
        "algorithm": "RSA-PKCS1v15-SHA256",
        "key_size": 2048
    }

@app.post("/api/firmware/upload")
async def upload_firmware(
    file: UploadFile = File(...),
    version: str = None,
    description: str = None,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"DEBUG: Received version parameter: '{version}'")
    logger.info(f"DEBUG: Received description parameter: '{description}'")
    if not file.filename.endswith('.bin'):
        raise HTTPException(status_code=400, detail="Only .bin files allowed")

    safe_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    file_path = os.path.join(FIRMWARE_DIR, safe_filename)
    
    try:
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        file_hash = calculate_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        signature_service = get_signature_service()
        signature_data = signature_service.create_signature_data(file_path, version or "1.0.0")
        
        if not signature_data:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise HTTPException(status_code=500, detail="Failed to create firmware signature")
        
        db = load_firmware_db()
        firmware_id = len(db["firmwares"]) + 1
        
        firmware_info = {
            "id": firmware_id,
            "filename": safe_filename,
            "original_filename": file.filename,
            "version": version or "1.0.0",
            "description": description or "No description",
            "upload_time": datetime.now().isoformat(),
            "file_size": file_size,
            "sha256": file_hash,
            "download_count": 0,
            "signature_created": True,
            "signature_algorithm": "RSA-PKCS1v15-SHA256"
        }
        
        db["firmwares"].append(firmware_info)
        save_firmware_db(db)
        
        signature_service.save_signature_file(signature_data, firmware_id)
        
        logger.info(f"Firmware uploaded and signed: {safe_filename} (ID: {firmware_id})")
        
        return {
            "message": "Firmware uploaded and signed successfully",
            "firmware": firmware_info,
            "signature": {
                "algorithm": signature_data["algorithm"],
                "created_at": signature_data["created_at"],
                "size_bytes": signature_data["firmware_size"]
            }
        }
        
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        logger.error(f"Firmware upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/firmware/list")
async def list_firmwares():
    db = load_firmware_db()
    return {"firmwares": db["firmwares"]}

@app.get("/api/firmware/latest")
async def get_latest_firmware():
    db = load_firmware_db()
    if not db["firmwares"]:
        raise HTTPException(status_code=404, detail="No firmware found")
    
    latest = max(db["firmwares"], key=lambda x: x["upload_time"])
    return {"firmware": latest}

@app.get("/api/firmware/check/{current_version}")
async def check_update(current_version: str):
    db = load_firmware_db()
    if not db["firmwares"]:
        return {"update_available": False, "message": "No firmware available"}
    
    latest = max(db["firmwares"], key=lambda x: x["upload_time"])
    update_available = latest["version"] != current_version
    
    response = {
        "update_available": update_available,
        "current_version": current_version,
        "latest_version": latest["version"],
        "message": "Update available" if update_available else "Up to date"
    }
    
    if update_available:
        response["id"] = latest["id"]
        response["firmware_size"] = latest["file_size"]
        response["signature_algorithm"] = latest.get("signature_algorithm", "RSA-PKCS1v15-SHA256")
    
    return response

@app.get("/api/firmware/signature/{firmware_id}")
async def get_firmware_signature(firmware_id: int):
    signature_service = get_signature_service()
    signature_data = signature_service.load_signature_file(firmware_id)
    
    if not signature_data:
        raise HTTPException(status_code=404, detail="Signature not found")
    
    logger.info(f"Signature data served for firmware ID: {firmware_id}")
    return signature_data

@app.get("/api/firmware/download/{firmware_id}")
async def download_firmware(firmware_id: int, request: Request):
    db = load_firmware_db()
    
    firmware = None
    for fw in db["firmwares"]:
        if fw["id"] == firmware_id:
            firmware = fw
            break
    
    if not firmware:
        raise HTTPException(status_code=404, detail="Firmware not found")
    
    file_path = os.path.join(FIRMWARE_DIR, firmware["filename"])
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Firmware file not found")
    
    firmware["download_count"] += 1
    save_firmware_db(db)
    
    client_ip = request.client.host
    logger.info(f"Firmware downloaded: {firmware['filename']} by {client_ip}")
    
    return FileResponse(
        file_path,
        media_type='application/octet-stream',
        filename=firmware["original_filename"],
        headers={
            "Content-SHA256": firmware["sha256"],
            "Content-Length": str(firmware["file_size"]),
            "X-Firmware-Signed": "true",
            "X-Signature-Algorithm": firmware.get("signature_algorithm", "RSA-PKCS1v15-SHA256")
        }
    )

@app.delete("/api/firmware/{firmware_id}")
async def delete_firmware(firmware_id: int, api_key: str = Depends(verify_api_key)):
    db = load_firmware_db()
    
    firmware_index = None
    for i, fw in enumerate(db["firmwares"]):
        if fw["id"] == firmware_id:
            firmware_index = i
            break
    
    if firmware_index is None:
        raise HTTPException(status_code=404, detail="Firmware not found")
    
    firmware = db["firmwares"][firmware_index]
    file_path = os.path.join(FIRMWARE_DIR, firmware["filename"])
    
    if os.path.exists(file_path):
        os.remove(file_path)
    
    signatures_dir = "/opt/esp32-ota-server/signatures"
    signature_file = os.path.join(signatures_dir, f"firmware_{firmware_id}.sig.json")
    if os.path.exists(signature_file):
        os.remove(signature_file)
    
    db["firmwares"].pop(firmware_index)
    save_firmware_db(db)
    
    logger.info(f"Firmware and signature deleted: {firmware['filename']}")
    return {"message": "Firmware and signature deleted successfully"}

@app.get("/api/firmware/verify/{firmware_id}")
async def verify_firmware_signature(firmware_id: int):
    db = load_firmware_db()
    signature_service = get_signature_service()
    
    firmware = None
    for fw in db["firmwares"]:
        if fw["id"] == firmware_id:
            firmware = fw
            break
    
    if not firmware:
        raise HTTPException(status_code=404, detail="Firmware not found")
    
    file_path = os.path.join(FIRMWARE_DIR, firmware["filename"])
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Firmware file not found")
    
    signature_data = signature_service.load_signature_file(firmware_id)
    if not signature_data:
        raise HTTPException(status_code=404, detail="Signature not found")
    
    try:
        with open(file_path, 'rb') as f:
            firmware_data = f.read()
        
        import base64
        signature_bytes = base64.b64decode(signature_data["signature"])
        is_valid = signature_service.verify_signature(firmware_data, signature_bytes)
        
        return {
            "firmware_id": firmware_id,
            "filename": firmware["filename"],
            "signature_valid": is_valid,
            "algorithm": signature_data["algorithm"],
            "verification_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        raise HTTPException(status_code=500, detail="Signature verification failed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
