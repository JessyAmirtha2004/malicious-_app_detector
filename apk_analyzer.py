"""
APK Analyzer Module
Comprehensive APK analysis including permissions, certificates, network security, and code analysis.
"""

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
import re
import hashlib
import math
from typing import Dict, List, Any
from datetime import datetime


class APKAnalyzer:
    """Comprehensive APK analysis class"""
    
    # Categorized dangerous permissions
    DANGEROUS_PERMISSIONS = {
        'sms': [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.RECEIVE_MMS',
            'android.permission.RECEIVE_WAP_PUSH'
        ],
        'phone': [
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.READ_PHONE_STATE',
            'android.permission.PROCESS_OUTGOING_CALLS'
        ],
        'contacts': [
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS'
        ],
        'location': [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.ACCESS_BACKGROUND_LOCATION'
        ],
        'camera_audio': [
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO'
        ],
        'storage': [
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.MANAGE_EXTERNAL_STORAGE'
        ],
        'system': [
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.INSTALL_PACKAGES',
            'android.permission.DELETE_PACKAGES',
            'android.permission.WRITE_SETTINGS',
            'android.permission.WRITE_SECURE_SETTINGS',
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.BIND_ACCESSIBILITY_SERVICE'
        ],
        'sensors': [
            'android.permission.BODY_SENSORS',
            'android.permission.ACTIVITY_RECOGNITION'
        ],
        'calendar': [
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR'
        ]
    }
    
    # Suspicious strings (shell commands, malicious domains, etc.)
    SUSPICIOUS_STRINGS = [
        'su', 'chmod', 'chown', 'remount', '/system/bin/sh', '/system/xbin/su',
        'mount -o remount,rw', 'busybox', 'nc -l', 'reverse_shell',
        'wget', 'curl -O', 'python -c', 'perl -e', 'ruby -e',
        'Runtime.getRuntime().exec', 'ProcessBuilder',
        '.onion', 'pastebin.com', 'ngrok.io', 'bit.ly', 'goo.gl',
        'temp-mail.org', 'dispostable.com', '10minutemail.com'
    ]
    
    # High-risk Android API calls
    HIGH_RISK_APIS = [
        'Ljava/lang/Runtime;->exec',
        'Ljava/lang/ProcessBuilder;->start',
        'Ldalvik/system/DexClassLoader;',
        'Ldalvik/system/PathClassLoader;',
        'Landroid/telephony/SmsManager;->sendTextMessage',
        'Landroid/telephony/SmsManager;->sendDataMessage',
        'Landroid/content/ContentResolver;->query',
        'Landroid/location/LocationManager;->getLastKnownLocation',
        'Landroid/hardware/Camera;->takePicture',
        'Landroid/media/MediaRecorder;->start',
        'Landroid/net/wifi/WifiManager;->setWifiEnabled',
        'Landroid/app/admin/DevicePolicyManager;->lockNow'
    ]
    
    def __init__(self, apk_path: str):
        """Initialize analyzer with APK file path"""
        self.apk_path = apk_path
        self.apk = APK(apk_path)
        
    def analyze_permissions(self) -> Dict[str, Any]:
        """Analyze APK permissions and categorize them"""
        all_permissions = self.apk.get_permissions()
        
        # Flatten dangerous permissions list
        all_dangerous = []
        for category_perms in self.DANGEROUS_PERMISSIONS.values():
            all_dangerous.extend(category_perms)
        
        # Find dangerous permissions
        dangerous_found = []
        dangerous_by_category = {}
        
        for perm in all_permissions:
            for category, category_perms in self.DANGEROUS_PERMISSIONS.items():
                if perm in category_perms:
                    dangerous_found.append(perm)
                    if category not in dangerous_by_category:
                        dangerous_by_category[category] = []
                    dangerous_by_category[category].append(perm)
        
        return {
            'all_permissions': all_permissions,
            'total_count': len(all_permissions),
            'dangerous_permissions': dangerous_found,
            'dangerous_count': len(dangerous_found),
            'dangerous_by_category': dangerous_by_category,
            'safe_permissions': [p for p in all_permissions if p not in dangerous_found]
        }
    
    def analyze_certificate(self) -> Dict[str, Any]:
        """Analyze APK certificate information"""
        try:
            cert = self.apk.get_certificate_der(self.apk.get_signature_names()[0])
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            cert_obj = x509.load_der_x509_certificate(cert, default_backend())
            
            issuer = cert_obj.issuer.rfc4514_string()
            subject = cert_obj.subject.rfc4514_string()
            
            # Check if self-signed
            is_self_signed = issuer == subject
            
            # Check if debug certificate
            is_debug = 'CN=Android Debug' in subject or 'Android Debug' in issuer
            
            # Get validity dates
            valid_from = cert_obj.not_valid_before.isoformat()
            valid_to = cert_obj.not_valid_after.isoformat()
            
            # Check if expired
            is_expired = datetime.now() > cert_obj.not_valid_after
            
            return {
                'issuer': issuer,
                'subject': subject,
                'is_self_signed': is_self_signed,
                'is_debug': is_debug,
                'is_expired': is_expired,
                'valid_from': valid_from,
                'valid_to': valid_to,
                'serial_number': str(cert_obj.serial_number),
                'version': cert_obj.version.value
            }
        except Exception as e:
            return {
                'error': f'Certificate analysis failed: {str(e)}',
                'issuer': 'Unknown',
                'subject': 'Unknown',
                'is_self_signed': False,
                'is_debug': False,
                'is_expired': False
            }
    
    def analyze_network_security(self) -> Dict[str, Any]:
        """Analyze network security configuration"""
        try:
            # Look for hardcoded IPs
            hardcoded_ips = []
            hardcoded_urls = []
            
            # IP pattern (simple regex)
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            url_pattern = r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            
            # Check AndroidManifest for cleartext traffic
            manifest = self.apk.get_android_manifest_xml()
            allow_cleartext = False
            
            if manifest:
                manifest_str = str(manifest)
                if 'usesCleartextTraffic' in manifest_str:
                    allow_cleartext = 'true' in manifest_str.lower()
            
            # Try to extract strings from DEX files to find IPs and URLs
            try:
                dex_files = self.apk.get_all_dex()
                for dex in dex_files[:3]:  # Limit to first 3 DEX files for performance
                    d = DalvikVMFormat(dex)
                    strings = d.get_strings()
                    for s in strings[:1000]:  # Limit strings analyzed
                        # Find IPs
                        ip_matches = re.findall(ip_pattern, s)
                        for ip in ip_matches:
                            if ip not in hardcoded_ips and not ip.startswith('0.'):
                                hardcoded_ips.append(ip)
                        
                        # Find URLs
                        url_matches = re.findall(url_pattern, s)
                        for url in url_matches:
                            if url not in hardcoded_urls:
                                hardcoded_urls.append(url)
            except:
                pass  # Skip if DEX parsing fails
            
            return {
                'hardcoded_ips': hardcoded_ips[:10],  # Limit to first 10
                'hardcoded_urls': hardcoded_urls[:10],  # Limit to first 10
                'allows_cleartext_traffic': allow_cleartext,
                'has_network_concerns': len(hardcoded_ips) > 0 or allow_cleartext
            }
        except Exception as e:
            return {
                'error': f'Network analysis failed: {str(e)}',
                'hardcoded_ips': [],
                'hardcoded_urls': [],
                'allows_cleartext_traffic': False,
                'has_network_concerns': False
            }
    
    def analyze_components(self) -> Dict[str, Any]:
        """Analyze Android components"""
        return {
            'activities': self.apk.get_activities(),
            'activities_count': len(self.apk.get_activities()),
            'services': self.apk.get_services(),
            'services_count': len(self.apk.get_services()),
            'receivers': self.apk.get_receivers(),
            'receivers_count': len(self.apk.get_receivers()),
            'providers': self.apk.get_providers(),
            'providers_count': len(self.apk.get_providers())
        }
    
    def analyze_code(self) -> Dict[str, Any]:
        """Analyze code characteristics"""
        try:
            # Get native libraries
            native_libs = {}
            libs = self.apk.get_files()
            
            for lib_path in libs:
                if lib_path.startswith('lib/'):
                    parts = lib_path.split('/')
                    if len(parts) >= 3:
                        arch = parts[1]
                        lib_name = parts[2]
                        if arch not in native_libs:
                            native_libs[arch] = []
                        native_libs[arch].append(lib_name)
            
            # Check for code obfuscation indicators
            has_obfuscation = False
            obfuscation_indicators = []
            
            activities = self.apk.get_activities()
            # Check for short/single character class names (common in obfuscated code)
            for activity in activities[:20]:  # Check first 20
                parts = activity.split('.')
                if parts:
                    class_name = parts[-1]
                    if len(class_name) <= 2 and class_name.islower():
                        has_obfuscation = True
                        obfuscation_indicators.append(f'Short class name: {class_name}')
                        break
            
            return {
                'native_libraries': native_libs,
                'native_lib_count': sum(len(libs) for libs in native_libs.values()),
                'architectures': list(native_libs.keys()),
                'has_obfuscation': has_obfuscation,
                'obfuscation_indicators': obfuscation_indicators
            }
        except Exception as e:
            return {
                'error': f'Code analysis failed: {str(e)}',
                'native_libraries': {},
                'native_lib_count': 0,
                'architectures': [],
                'has_obfuscation': False,
                'obfuscation_indicators': []
            }
            
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for a given byte sequence"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def analyze_entropy(self) -> Dict[str, Any]:
        """Analyze entropy of DEX files to detect packing/encryption"""
        try:
            dex_entropies = []
            max_entropy = 0
            
            dex_files = self.apk.get_all_dex()
            for i, dex in enumerate(dex_files):
                entropy = self.calculate_entropy(dex)
                dex_entropies.append({
                    'name': f'classes{i+1 if i > 0 else ""}.dex',
                    'entropy': round(entropy, 4)
                })
                max_entropy = max(max_entropy, entropy)
            
            # High entropy (typically > 7.2) suggests packing or encryption
            is_packed = max_entropy > 7.2
            
            return {
                'dex_entropies': dex_entropies,
                'max_entropy': round(max_entropy, 4),
                'is_likely_packed': is_packed,
                'threshold': 7.2
            }
        except Exception as e:
            return {'error': str(e), 'dex_entropies': [], 'max_entropy': 0, 'is_likely_packed': False}

    def analyze_strings_and_apis(self) -> Dict[str, Any]:
        """Analyze suspicious strings and high-risk API usage"""
        found_strings = []
        found_apis = []
        
        try:
            dex_files = self.apk.get_all_dex()
            for dex in dex_files[:2]:  # Check first 2 DEX files for performance
                d = DalvikVMFormat(dex)
                
                # Check strings
                all_strings = d.get_strings()
                for s in all_strings:
                    for suspect in self.SUSPICIOUS_STRINGS:
                        if suspect in s and suspect not in found_strings:
                            found_strings.append(suspect)
                
                # Check APIs
                methods = d.get_methods()
                for m in methods:
                    for risk_api in self.HIGH_RISK_APIS:
                        if risk_api in m.get_descriptor() or risk_api in m.get_name():
                            if risk_api not in found_apis:
                                found_apis.append(risk_api)
        except:
            pass
            
        return {
            'suspicious_strings': found_strings[:20],
            'suspicious_string_count': len(found_strings),
            'high_risk_apis': found_apis,
            'api_misuse_count': len(found_apis)
        }

    def check_threat_intel(self) -> Dict[str, Any]:
        """Check VirusTotal and OSINT (Mocked implementation)"""
        # In a real scenario, we would use requests to query VT and AbuseIPDB
        # For now, we provide placeholders and logic based on existing data
        
        file_hashes = self.get_metadata()
        sha256 = file_hashes['sha256']
        
        # Placeholder for real VT check
        vt_data = {
            'positives': 0,
            'total': 72,
            'permalink': f'https://www.virustotal.com/gui/file/{sha256}',
            'status': 'Clean (Mock)'
        }
        
        # Placeholder for real IP reputation check
        ip_rep = []
        network = self.analyze_network_security()
        for ip in network.get('hardcoded_ips', [])[:3]:
            ip_rep.append({
                'ip': ip,
                'reputation_score': 0,
                'is_malicious': False,
                'source': 'AbuseIPDB (Mock)'
            })
            
        return {
            'virustotal': vt_data,
            'ip_reputation': ip_rep,
            'last_check': datetime.now().isoformat()
        }

    def get_metadata(self) -> Dict[str, Any]:
        """Extract APK metadata"""
        import os
        
        file_size = os.path.getsize(self.apk_path)
        
        # Calculate file hashes
        with open(self.apk_path, 'rb') as f:
            file_data = f.read()
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        return {
            'app_name': self.apk.get_app_name(),
            'package_name': self.apk.get_package(),
            'version_code': self.apk.get_androidversion_code(),
            'version_name': self.apk.get_androidversion_name(),
            'min_sdk_version': self.apk.get_min_sdk_version(),
            'target_sdk_version': self.apk.get_target_sdk_version(),
            'file_size': file_size,
            'file_size_mb': round(file_size / (1024 * 1024), 2),
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash
        }
    
    def calculate_risk_score(self, perm_analysis: Dict, cert_analysis: Dict, 
                           network_analysis: Dict, code_analysis: Dict,
                           entropy_analysis: Dict, string_api_analysis: Dict,
                           threat_intel: Dict) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score based on multiple factors
        Scoring: 0-100 scale
        - Permissions: 30% weight
        - Certificate: 15% weight
        - Network: 15% weight
        - Code/Entropy: 15% weight
        - Strings/API Misuse: 15% weight
        - Threat Intel: 10% weight
        """
        
        # Permission score (0-30)
        perm_score = 0
        dangerous_count = perm_analysis['dangerous_count']
        perm_score = min(dangerous_count * 3, 20)
        
        dangerous_by_cat = perm_analysis['dangerous_by_category']
        if 'system' in dangerous_by_cat and len(dangerous_by_cat['system']) > 0:
            perm_score += 7
        if 'sms' in dangerous_by_cat and len(dangerous_by_cat['sms']) > 1:
            perm_score += 3
        perm_score = min(perm_score, 30)
        
        # Certificate score (0-15)
        cert_score = 0
        if cert_analysis.get('is_debug'):
            cert_score += 10
        if cert_analysis.get('is_self_signed') and not cert_analysis.get('is_debug'):
            cert_score += 3
        if cert_analysis.get('is_expired'):
            cert_score += 5
        cert_score = min(cert_score, 15)
        
        # Network score (0-15)
        network_score = 0
        if network_analysis.get('allows_cleartext_traffic'):
            network_score += 5
        ip_count = len(network_analysis.get('hardcoded_ips', []))
        if ip_count > 0:
            network_score += min(ip_count * 2, 10)
        network_score = min(network_score, 15)
        
        # Code & Entropy score (0-15)
        code_score = 0
        if code_analysis.get('has_obfuscation'):
            code_score += 5
        if entropy_analysis.get('is_likely_packed'):
            code_score += 10
        code_score = min(code_score, 15)
        
        # Strings & API Misuse score (0-15)
        misuse_score = 0
        string_count = string_api_analysis.get('suspicious_string_count', 0)
        api_count = string_api_analysis.get('api_misuse_count', 0)
        
        misuse_score += min(string_count * 1, 7)
        misuse_score += min(api_count * 2, 8)
        misuse_score = min(misuse_score, 15)

        # Threat Intel score (0-10)
        intel_score = 0
        vt_positives = threat_intel.get('virustotal', {}).get('positives', 0)
        if vt_positives > 0:
            intel_score += 10
        elif any(ip['is_malicious'] for ip in threat_intel.get('ip_reputation', [])):
            intel_score += 8
        intel_score = min(intel_score, 10)
        
        # Total risk score
        total_score = perm_score + cert_score + network_score + code_score + misuse_score + intel_score
        
        # Determine risk level
        if total_score >= 70:
            risk_level = 'Critical'
        elif total_score >= 45:
            risk_level = 'High'
        elif total_score >= 20:
            risk_level = 'Medium'
        elif total_score >= 8:
            risk_level = 'Low'
        else:
            risk_level = 'Safe'
        
        return {
            'risk_score': round(total_score, 1),
            'risk_level': risk_level,
            'score_breakdown': {
                'permissions': round(perm_score, 1),
                'certificate': round(cert_score, 1),
                'network': round(network_score, 1),
                'code_entropy': round(code_score, 1),
                'api_misuse': round(misuse_score, 1),
                'threat_intel': round(intel_score, 1)
            }
        }
    
    def analyze_full(self) -> Dict[str, Any]:
        """Perform comprehensive APK analysis"""
        try:
            # Get all analyses
            metadata = self.get_metadata()
            permissions = self.analyze_permissions()
            certificate = self.analyze_certificate()
            network = self.analyze_network_security()
            components = self.analyze_components()
            code = self.analyze_code()
            entropy = self.analyze_entropy()
            strings_apis = self.analyze_strings_and_apis()
            threat_intel = self.check_threat_intel()
            
            risk = self.calculate_risk_score(
                permissions, certificate, network, code, 
                entropy, strings_apis, threat_intel
            )
            
            return {
                'success': True,
                'metadata': metadata,
                'permissions': permissions,
                'certificate': certificate,
                'network_security': network,
                'components': components,
                'code_analysis': code,
                'entropy_analysis': entropy,
                'strings_apis': strings_apis,
                'threat_intel': threat_intel,
                'risk_assessment': risk
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__
            }
