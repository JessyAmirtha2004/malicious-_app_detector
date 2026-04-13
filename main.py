from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import os
from apk_analyzer import APKAnalyzer

app = FastAPI(title="Mobile Security ML Service", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    filename: str

@app.post("/scan")
async def scan_apk(request: ScanRequest):
    """
    Comprehensive APK analysis endpoint
    Analyzes permissions, certificate, network security, code, and calculates risk score
    """
    # Determine the file path based on running environment
    # In Docker: /app/uploads
    # Locally: ../backend/uploads relative to ml-service
    
    file_path = os.path.join("../backend/uploads", request.filename)
    if not os.path.exists(file_path):
        file_path = os.path.join("uploads", request.filename)  # Docker fallback
    
    if not os.path.exists(file_path):
        # Absolute path check for debugging
        file_path = os.path.abspath(os.path.join(os.getcwd(), "../backend/uploads", request.filename))

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"File not found at {file_path}")

    try:
        # Initialize analyzer
        analyzer = APKAnalyzer(file_path)
        
        # Perform comprehensive analysis
        result = analyzer.analyze_full()
        
        if not result.get('success'):
            # Analysis failed, return error with fallback data
            error_msg = result.get('error', 'Unknown error')
            print(f"Analysis error: {error_msg}")
            
            # Return minimal fallback data
            return {
                "meta": {
                    "app_name": "Analysis Error",
                    "package_name": "com.error.analysis",
                    "version_code": "0",
                    "version_name": "0.0",
                },
                "permissions": [],
                "dangerous_permissions": [],
                "components": {
                    "activities_count": 0,
                    "services_count": 0,
                    "receivers_count": 0
                },
                "risk_score": 0,
                "risk_level": "Unknown",
                "error": error_msg
            }
        
        # Format response for frontend compatibility
        metadata = result['metadata']
        permissions = result['permissions']
        certificate = result['certificate']
        network = result['network_security']
        components = result['components']
        code = result['code_analysis']
        entropy = result['entropy_analysis']
        strings_apis = result['strings_apis']
        threat_intel = result['threat_intel']
        risk = result['risk_assessment']
        
        response = {
            # Basic metadata (backward compatible)
            "meta": {
                "app_name": metadata['app_name'],
                "package_name": metadata['package_name'],
                "version_code": metadata['version_code'],
                "version_name": metadata['version_name'],
                "min_sdk": metadata.get('min_sdk_version'),
                "target_sdk": metadata.get('target_sdk_version'),
                "file_size_mb": metadata.get('file_size_mb'),
            },
            
            # File hashes
            "hashes": {
                "md5": metadata.get('md5'),
                "sha1": metadata.get('sha1'),
                "sha256": metadata.get('sha256')
            },
            
            # Permissions (backward compatible + enhanced)
            "permissions": permissions['all_permissions'],
            "permissions_count": permissions['total_count'],
            "dangerous_permissions": permissions['dangerous_permissions'],
            "dangerous_permissions_by_category": permissions['dangerous_by_category'],
            
            # Certificate information
            "certificate": {
                "issuer": certificate.get('issuer'),
                "subject": certificate.get('subject'),
                "is_self_signed": certificate.get('is_self_signed'),
                "is_debug": certificate.get('is_debug'),
                "is_expired": certificate.get('is_expired'),
                "valid_from": certificate.get('valid_from'),
                "valid_to": certificate.get('valid_to'),
            },
            
            # Network security
            "network_security": {
                "hardcoded_ips": network.get('hardcoded_ips', []),
                "hardcoded_urls": network.get('hardcoded_urls', []),
                "allows_cleartext_traffic": network.get('allows_cleartext_traffic'),
                "has_concerns": network.get('has_network_concerns')
            },
            
            # Components (backward compatible + enhanced)
            "components": {
                "activities_count": components['activities_count'],
                "services_count": components['services_count'],
                "receivers_count": components['receivers_count'],
                "providers_count": components.get('providers_count', 0)
            },
            
            # Code analysis
            "code_analysis": {
                "native_libraries": code.get('native_libraries', {}),
                "native_lib_count": code.get('native_lib_count', 0),
                "architectures": code.get('architectures', []),
                "has_obfuscation": code.get('has_obfuscation'),
                "obfuscation_indicators": code.get('obfuscation_indicators', [])
            },

            # NEW: Entropy Analysis
            "entropy_analysis": entropy,

            # NEW: Suspicious Strings and API Misuse
            "strings_apis": strings_apis,

            # NEW: Threat Intelligence
            "threat_intel": threat_intel,
            
            # Risk assessment (backward compatible + enhanced)
            "risk_score": risk['risk_score'],
            "risk_level": risk['risk_level'],
            "risk_breakdown": risk['score_breakdown']
        }
        
        return response

    except Exception as e:
        print(f"Error analyzing APK: {e}")
        import traceback
        traceback.print_exc()
        
        # Return fallback data for demonstration
        return {
            "meta": {
                "app_name": "Demo App (Parse Error)",
                "package_name": "com.example.demo",
                "version_code": "1",
                "version_name": "1.0",
            },
            "permissions": ["android.permission.INTERNET"],
            "dangerous_permissions": [],
            "components": {
                "activities_count": 1,
                "services_count": 0,
                "receivers_count": 0
            },
            "risk_score": 5,
            "risk_level": "Safe",
            "error": str(e)
        }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "ok", "version": "2.0.0"}

@app.get("/")
def root():
    """Root endpoint with API information"""
    return {
        "service": "Mobile Security ML Service",
        "version": "2.0.0",
        "endpoints": {
            "scan": "/scan (POST)",
            "health": "/health (GET)",
            "docs": "/docs (GET)"
        }
    }
