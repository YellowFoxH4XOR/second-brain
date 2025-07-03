#!/usr/bin/env python3
"""
F5 BIG-IP Certificate Cleanup Script

This script automates the process of identifying, analyzing, and safely removing
expired SSL certificates from F5 BIG-IP devices using the iControl REST API.

Features:
- Identify expiring/expired certificates
- Check certificate usage across LTM/GTM objects
- Generate HTML pre-deletion report
- Safe deletion with dereferencing
- Replace with default certificates where needed

Author: Generated for Certificate Cleanup Automation
Version: 1.0
"""

import requests
import datetime
import urllib3
import json
import sys
import os
import argparse
import getpass
import csv
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class CertificateInfo:
    """Data class to hold certificate information"""
    name: str
    full_path: str
    expiration_date: datetime.datetime
    days_until_expiry: int
    is_expired: bool
    is_expiring_soon: bool
    subject: str = ""
    issuer: str = ""

@dataclass
class CertificateUsage:
    """Data class to hold certificate usage information"""
    object_type: str
    object_name: str
    object_path: str
    field_name: str
    partition: str = "Common"

@dataclass
class DeviceInfo:
    """Data class to hold F5 device information"""
    hostname: str
    ip_address: str
    username: str = ""
    password: str = ""
    
@dataclass
class CleanupReport:
    """Data class for cleanup report"""
    device_hostname: str
    device_ip: str
    total_certificates: int
    expired_certificates: List[CertificateInfo]
    expiring_certificates: List[CertificateInfo]
    unused_expired: List[CertificateInfo]
    used_expired: List[Tuple[CertificateInfo, List[CertificateUsage]]]
    scan_timestamp: datetime.datetime
    connection_successful: bool = True
    error_message: str = ""

@dataclass
class BatchCleanupReport:
    """Data class for batch cleanup report across multiple devices"""
    reports: List[CleanupReport]
    total_devices: int
    successful_devices: int
    failed_devices: int
    scan_timestamp: datetime.datetime

def read_devices_csv(csv_file: str) -> List[DeviceInfo]:
    """
    Read F5 device information from CSV file
    
    Args:
        csv_file: Path to CSV file containing device information
        
    Returns:
        List of DeviceInfo objects
    """
    devices = []
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                # Support flexible column names
                hostname = row.get('hostname') or row.get('Hostname') or row.get('HOSTNAME')
                ip_address = row.get('ip') or row.get('ip_address') or row.get('IP') or row.get('IP_Address')
                username = row.get('username') or row.get('Username') or row.get('USER') or ""
                password = row.get('password') or row.get('Password') or row.get('PASS') or ""
                
                if not hostname and not ip_address:
                    print(f"⚠️  Warning: Skipping row with missing hostname and IP: {row}")
                    continue
                
                # Use IP if hostname not provided, or vice versa
                if not hostname:
                    hostname = ip_address
                if not ip_address:
                    ip_address = hostname
                
                devices.append(DeviceInfo(
                    hostname=hostname,
                    ip_address=ip_address,
                    username=username,
                    password=password
                ))
        
        print(f"📋 Loaded {len(devices)} device(s) from {csv_file}")
        return devices
        
    except FileNotFoundError:
        print(f"❌ CSV file not found: {csv_file}")
        return []
    except Exception as e:
        print(f"❌ Error reading CSV file {csv_file}: {e}")
        return []

class F5CertificateCleanup:
    """Main class for F5 certificate cleanup operations"""
    
    def __init__(self, host: str, username: str, password: str, expiry_days: int = 30, test_connection: bool = True):
        """
        Initialize F5 connection and configuration
        
        Args:
            host: F5 BIG-IP hostname or IP
            username: F5 username
            password: F5 password
            expiry_days: Days ahead to consider certificates as "expiring soon"
            test_connection: Whether to test connection during initialization
        """
        self.original_host = host
        self.host = host.rstrip('/')
        if not self.host.startswith('https://'):
            self.host = f"https://{self.host}"
        
        self.auth = (username, password)
        self.expiry_days = expiry_days
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = False
        
        # Test connection if requested
        if test_connection:
            try:
                self._test_connection()
            except Exception as e:
                print(f"❌ Failed to connect to F5 device: {e}")
                sys.exit(1)
    
    def _test_connection(self):
        """Test F5 API connectivity"""
        response = self.session.get(f"{self.host}/mgmt/tm/sys/version")
        response.raise_for_status()
        print(f"✅ Connected to F5 BIG-IP: {self.host}")
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make authenticated request to F5 API"""
        url = f"{self.host}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    
    def discover_certificates(self) -> List[CertificateInfo]:
        """
        Discover all SSL certificates on the F5 device
        
        Returns:
            List of CertificateInfo objects
        """
        print("🔍 Discovering SSL certificates...")
        
        response = self._make_request('GET', '/mgmt/tm/sys/file/ssl-cert')
        certificates = []
        
        for cert_data in response.json().get('items', []):
            try:
                # Parse expiration date
                exp_timestamp = cert_data.get('expirationDate', 0)
                exp_date = datetime.datetime.fromtimestamp(exp_timestamp)
                
                # Calculate days until expiry
                now = datetime.datetime.now()
                days_until_expiry = (exp_date - now).days
                
                cert_info = CertificateInfo(
                    name=cert_data['name'],
                    full_path=cert_data['fullPath'],
                    expiration_date=exp_date,
                    days_until_expiry=days_until_expiry,
                    is_expired=days_until_expiry < 0,
                    is_expiring_soon=0 <= days_until_expiry <= self.expiry_days,
                    subject=cert_data.get('subject', ''),
                    issuer=cert_data.get('issuer', '')
                )
                
                certificates.append(cert_info)
                
            except Exception as e:
                print(f"⚠️  Warning: Could not process certificate {cert_data.get('name', 'unknown')}: {e}")
        
        print(f"📋 Found {len(certificates)} total certificates")
        return certificates
    
    def check_certificate_usage(self, cert_path: str) -> List[CertificateUsage]:
        """
        Check where a certificate is being used across F5 configuration
        
        Args:
            cert_path: Full path of certificate (e.g., '/Common/cert.crt')
            
        Returns:
            List of CertificateUsage objects
        """
        usage_list = []
        
        # Check Client-SSL profiles
        try:
            response = self._make_request('GET', '/mgmt/tm/ltm/profile/client-ssl')
            for profile in response.json().get('items', []):
                cert_key_chain = profile.get('certKeyChain', [])
                for chain in cert_key_chain:
                    if chain.get('cert') == cert_path:
                        usage_list.append(CertificateUsage(
                            object_type='Client-SSL Profile',
                            object_name=profile['name'],
                            object_path=profile['fullPath'],
                            field_name='certKeyChain.cert'
                        ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Client-SSL profiles: {e}")
        
        # Check Server-SSL profiles
        try:
            response = self._make_request('GET', '/mgmt/tm/ltm/profile/server-ssl')
            for profile in response.json().get('items', []):
                if profile.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Server-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='cert'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Server-SSL profiles: {e}")
        
        # Check LTM HTTPS monitors
        try:
            response = self._make_request('GET', '/mgmt/tm/ltm/monitor/https')
            for monitor in response.json().get('items', []):
                if monitor.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='LTM HTTPS Monitor',
                        object_name=monitor['name'],
                        object_path=monitor['fullPath'],
                        field_name='cert'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check LTM HTTPS monitors: {e}")
        
        # Check GTM HTTPS monitors
        try:
            response = self._make_request('GET', '/mgmt/tm/gtm/monitor/https')
            for monitor in response.json().get('items', []):
                if monitor.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='GTM HTTPS Monitor',
                        object_name=monitor['name'],
                        object_path=monitor['fullPath'],
                        field_name='cert'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check GTM HTTPS monitors: {e}")
        
        # Check OCSP responders
        try:
            response = self._make_request('GET', '/mgmt/tm/sys/crypto/cert-validator/ocsp')
            for ocsp in response.json().get('items', []):
                trusted_responders = ocsp.get('trustedResponders', [])
                if isinstance(trusted_responders, list):
                    for responder in trusted_responders:
                        if responder == cert_path:
                            usage_list.append(CertificateUsage(
                                object_type='OCSP Responder',
                                object_name=ocsp['name'],
                                object_path=ocsp['fullPath'],
                                field_name='trustedResponders'
                            ))
                elif trusted_responders == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='OCSP Responder',
                        object_name=ocsp['name'],
                        object_path=ocsp['fullPath'],
                        field_name='trustedResponders'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check OCSP responders: {e}")
        
        # Check APM authentication profiles
        try:
            response = self._make_request('GET', '/mgmt/tm/apm/profile/authentication')
            for auth_profile in response.json().get('items', []):
                if auth_profile.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='APM Authentication Profile',
                        object_name=auth_profile['name'],
                        object_path=auth_profile['fullPath'],
                        field_name='cert'
                    ))
                # Check trustedCAs field (can be array or single value)
                trusted_cas = auth_profile.get('trustedCAs', [])
                if isinstance(trusted_cas, list):
                    for ca in trusted_cas:
                        if ca == cert_path:
                            usage_list.append(CertificateUsage(
                                object_type='APM Authentication Profile',
                                object_name=auth_profile['name'],
                                object_path=auth_profile['fullPath'],
                                field_name='trustedCAs'
                            ))
                elif trusted_cas == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='APM Authentication Profile',
                        object_name=auth_profile['name'],
                        object_path=auth_profile['fullPath'],
                        field_name='trustedCAs'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check APM authentication profiles: {e}")
        
        # Check LDAP servers
        try:
            response = self._make_request('GET', '/mgmt/tm/auth/ldap')
            for ldap in response.json().get('items', []):
                if ldap.get('sslCaCertFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='LDAP Server',
                        object_name=ldap['name'],
                        object_path=ldap['fullPath'],
                        field_name='sslCaCertFile'
                    ))
                if ldap.get('sslClientCert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='LDAP Server',
                        object_name=ldap['name'],
                        object_path=ldap['fullPath'],
                        field_name='sslClientCert'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check LDAP servers: {e}")
        
        # Check RADIUS servers
        try:
            response = self._make_request('GET', '/mgmt/tm/auth/radius-server')
            for radius in response.json().get('items', []):
                server_config = radius.get('server', {})
                if server_config.get('sslCaCertFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='RADIUS Server',
                        object_name=radius['name'],
                        object_path=radius['fullPath'],
                        field_name='server.sslCaCertFile'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check RADIUS servers: {e}")
        
        # Check Syslog destinations
        try:
            response = self._make_request('GET', '/mgmt/tm/sys/syslog')
            for syslog in response.json().get('items', []):
                remote_syslog = syslog.get('remotesyslog', {})
                if remote_syslog.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Syslog Destination',
                        object_name=syslog.get('name', 'syslog'),
                        object_path=syslog.get('fullPath', '/Common/syslog'),
                        field_name='remotesyslog.cert'
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Syslog destinations: {e}")
        
        return usage_list
    
    def analyze_certificates(self, certificates: List[CertificateInfo]) -> CleanupReport:
        """
        Analyze certificates for expiry and usage
        
        Args:
            certificates: List of discovered certificates
            
        Returns:
            CleanupReport with analysis results
        """
        print("🔬 Analyzing certificate usage...")
        
        expired_certs = [cert for cert in certificates if cert.is_expired]
        expiring_certs = [cert for cert in certificates if cert.is_expiring_soon]
        
        unused_expired = []
        used_expired = []
        
        for cert in expired_certs:
            print(f"  📋 Checking usage for: {cert.name}")
            usage = self.check_certificate_usage(cert.full_path)
            
            if not usage:
                unused_expired.append(cert)
                print(f"    ✅ Not in use - safe to delete")
            else:
                used_expired.append((cert, usage))
                print(f"    ⚠️  In use by {len(usage)} object(s)")
        
        return CleanupReport(
            device_hostname=self.original_host,
            device_ip=self.host,
            total_certificates=len(certificates),
            expired_certificates=expired_certs,
            expiring_certificates=expiring_certs,
            unused_expired=unused_expired,
            used_expired=used_expired,
            scan_timestamp=datetime.datetime.now()
        )
    
    def generate_html_report(self, report: CleanupReport, output_file: str = "f5_cert_cleanup_report.html"):
        """
        Generate HTML report for pre-deletion verification
        
        Args:
            report: CleanupReport object
            output_file: Output HTML file path
        """
        print(f"📄 Generating HTML report: {output_file}")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>F5 Certificate Cleanup Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1, h2 {{ color: #333; border-bottom: 2px solid #007acc; padding-bottom: 5px; }}
        .summary {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .cert-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        .cert-table th, .cert-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        .cert-table th {{ background-color: #007acc; color: white; }}
        .cert-table tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .expired {{ background-color: #ffebee !important; }}
        .expiring {{ background-color: #fff3e0 !important; }}
        .safe-delete {{ background-color: #e8f5e8 !important; }}
        .usage-details {{ background: #f8f9fa; padding: 10px; border-left: 4px solid #007acc; margin: 5px 0; }}
        .badge {{ padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; color: black; }}
        .badge-success {{ background: #28a745; color: white; }}
        .timestamp {{ color: #666; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 F5 BIG-IP Certificate Cleanup Report</h1>
        
        <div class="summary">
            <h3>📊 Summary</h3>
            <ul>
                <li><strong>Total Certificates:</strong> {report.total_certificates}</li>
                <li><strong>Expired Certificates:</strong> {len(report.expired_certificates)}</li>
                <li><strong>Expiring Soon ({self.expiry_days} days):</strong> {len(report.expiring_certificates)}</li>
                <li><strong>Safe to Delete (unused expired):</strong> {len(report.unused_expired)}</li>
                <li><strong>Require Dereferencing (used expired):</strong> {len(report.used_expired)}</li>
            </ul>
            <p class="timestamp">Report generated: {report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>🗑️ Certificates Safe for Direct Deletion</h2>
        <p>These expired certificates are not referenced by any F5 objects and can be safely deleted:</p>
        <table class="cert-table">
            <thead>
                <tr>
                    <th>Certificate Name</th>
                    <th>Expiration Date</th>
                    <th>Days Expired</th>
                    <th>Subject</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for cert in report.unused_expired:
            html_content += f"""
                <tr class="safe-delete">
                    <td>{cert.name}</td>
                    <td>{cert.expiration_date.strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{abs(cert.days_until_expiry)}</td>
                    <td>{cert.subject}</td>
                    <td><span class="badge badge-success">Safe Delete</span></td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2>⚠️ Certificates Requiring Dereferencing</h2>
        <p>These expired certificates are in use and require dereferencing before deletion:</p>
"""
        
        for cert, usage_list in report.used_expired:
            html_content += f"""
        <div class="usage-details">
            <h4>📋 {cert.name}</h4>
            <p><strong>Expiration:</strong> {cert.expiration_date.strftime('%Y-%m-%d %H:%M:%S')} 
               ({abs(cert.days_until_expiry)} days expired)</p>
            <p><strong>Subject:</strong> {cert.subject}</p>
            <p><strong>Used by {len(usage_list)} object(s):</strong></p>
            <ul>
"""
            for usage in usage_list:
                html_content += f"""
                <li><strong>{usage.object_type}:</strong> {usage.object_name} (field: {usage.field_name})</li>
"""
            html_content += """
            </ul>
        </div>
"""
        
        html_content += f"""
        
        <h2>⏰ Certificates Expiring Soon</h2>
        <p>These certificates will expire within {self.expiry_days} days:</p>
        <table class="cert-table">
            <thead>
                <tr>
                    <th>Certificate Name</th>
                    <th>Expiration Date</th>
                    <th>Days Until Expiry</th>
                    <th>Subject</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for cert in report.expiring_certificates:
            html_content += f"""
                <tr class="expiring">
                    <td>{cert.name}</td>
                    <td>{cert.expiration_date.strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{cert.days_until_expiry}</td>
                    <td>{cert.subject}</td>
                    <td><span class="badge badge-warning">Expiring Soon</span></td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2>🔧 Recommended Actions</h2>
        <ol>
            <li><strong>Review this report carefully</strong> - Verify all certificates marked for deletion</li>
            <li><strong>Direct deletion</strong> - Certificates in "Safe for Direct Deletion" can be removed immediately</li>
            <li><strong>Dereferencing</strong> - Certificates "Requiring Dereferencing" will be replaced with default certificates first</li>
            <li><strong>Backup consideration</strong> - Consider backing up certificates before deletion if rollback might be needed</li>
            <li><strong>Plan renewals</strong> - Schedule renewals for certificates expiring soon</li>
        </ol>
        
        <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-radius: 5px;">
            <h4>⚠️ Important Notes</h4>
            <ul>
                <li>This script will replace expired certificates with F5's default certificate (/Common/default.crt)</li>
                <li>Services using expired certificates may experience SSL warnings until proper certificates are installed</li>
                <li>Always test in a non-production environment first</li>
                <li>Maintain valid certificates for production services</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Report saved to: {os.path.abspath(output_file)}")
    
    def dereference_certificate(self, cert_path: str, usage: CertificateUsage) -> bool:
        """
        Dereference a certificate from an F5 object and replace with default
        
        Args:
            cert_path: Full path of certificate to dereference
            usage: CertificateUsage object describing where it's used
            
        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"  🔄 Dereferencing from {usage.object_type}: {usage.object_name}")
            
            if usage.object_type == 'Client-SSL Profile':
                # Replace in Client-SSL profile
                update_data = {
                    "certKeyChain": [
                        {
                            "name": "default",
                            "cert": "/Common/default.crt",
                            "key": "/Common/default.key"
                        }
                    ]
                }
                endpoint = f"/mgmt/tm/ltm/profile/client-ssl/{usage.object_name.replace('/', '~')}"
                
            elif usage.object_type == 'Server-SSL Profile':
                # Replace in Server-SSL profile
                update_data = {
                    "cert": "/Common/default.crt",
                    "key": "/Common/default.key"
                }
                endpoint = f"/mgmt/tm/ltm/profile/server-ssl/{usage.object_name.replace('/', '~')}"
                
            elif usage.object_type in ['LTM HTTPS Monitor', 'GTM HTTPS Monitor']:
                # Replace in monitor
                update_data = {
                    "cert": "/Common/default.crt"
                }
                if 'LTM' in usage.object_type:
                    endpoint = f"/mgmt/tm/ltm/monitor/https/{usage.object_name.replace('/', '~')}"
                else:
                    endpoint = f"/mgmt/tm/gtm/monitor/https/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'OCSP Responder':
                # Replace in OCSP responder
                update_data = {
                    "trustedResponders": ["/Common/default.crt"]
                }
                endpoint = f"/mgmt/tm/sys/crypto/cert-validator/ocsp/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'APM Authentication Profile':
                # Replace in APM authentication profile
                if usage.field_name == 'cert':
                    update_data = {
                        "cert": "/Common/default.crt"
                    }
                elif usage.field_name == 'trustedCAs':
                    update_data = {
                        "trustedCAs": ["/Common/default.crt"]
                    }
                endpoint = f"/mgmt/tm/apm/profile/authentication/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'LDAP Server':
                # Replace in LDAP server
                if usage.field_name == 'sslCaCertFile':
                    update_data = {
                        "sslCaCertFile": "/Common/default.crt"
                    }
                elif usage.field_name == 'sslClientCert':
                    update_data = {
                        "sslClientCert": "/Common/default.crt"
                    }
                endpoint = f"/mgmt/tm/auth/ldap/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'RADIUS Server':
                # Replace in RADIUS server
                update_data = {
                    "server": {
                        "sslCaCertFile": "/Common/default.crt"
                    }
                }
                endpoint = f"/mgmt/tm/auth/radius-server/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'Syslog Destination':
                # Replace in Syslog destination
                update_data = {
                    "remotesyslog": {
                        "cert": "/Common/default.crt"
                    }
                }
                endpoint = f"/mgmt/tm/sys/syslog"
            
            else:
                print(f"    ❌ Unknown object type: {usage.object_type}")
                return False
            
            response = self._make_request('PATCH', endpoint, json=update_data)
            print(f"    ✅ Successfully dereferenced")
            return True
            
        except Exception as e:
            print(f"    ❌ Failed to dereference: {e}")
            return False
    
    def delete_certificate(self, cert_name: str) -> bool:
        """
        Delete a certificate from F5
        
        Args:
            cert_name: Name of certificate to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # URL encode the certificate name
            encoded_name = cert_name.replace('/', '~')
            endpoint = f"/mgmt/tm/sys/file/ssl-cert/{encoded_name}"
            
            response = self._make_request('DELETE', endpoint)
            print(f"  ✅ Deleted certificate: {cert_name}")
            return True
            
        except Exception as e:
            print(f"  ❌ Failed to delete certificate {cert_name}: {e}")
            return False
    
    def execute_cleanup(self, report: CleanupReport) -> Dict[str, int]:
        """
        Execute the certificate cleanup based on user confirmation
        
        Args:
            report: CleanupReport object
            
        Returns:
            Dictionary with cleanup statistics
        """
        stats = {
            'deleted_unused': 0,
            'deleted_used': 0,
            'dereferenced': 0,
            'failed_dereference': 0,
            'failed_delete': 0
        }
        
        print("\n🧹 Starting certificate cleanup...")
        
        # Delete unused expired certificates directly
        if report.unused_expired:
            print(f"\n🗑️  Deleting {len(report.unused_expired)} unused expired certificates...")
            for cert in report.unused_expired:
                if self.delete_certificate(cert.name):
                    stats['deleted_unused'] += 1
                else:
                    stats['failed_delete'] += 1
        
        # Handle used expired certificates
        if report.used_expired:
            print(f"\n🔄 Processing {len(report.used_expired)} used expired certificates...")
            for cert, usage_list in report.used_expired:
                print(f"\n📋 Processing certificate: {cert.name}")
                
                # Dereference from all usage locations
                dereference_success = True
                for usage in usage_list:
                    if self.dereference_certificate(cert.full_path, usage):
                        stats['dereferenced'] += 1
                    else:
                        stats['failed_dereference'] += 1
                        dereference_success = False
                
                # Only delete if all dereferencing was successful
                if dereference_success:
                    if self.delete_certificate(cert.name):
                        stats['deleted_used'] += 1
                    else:
                        stats['failed_delete'] += 1
                else:
                    print(f"  ⚠️  Skipping deletion due to failed dereferencing")
        
        return stats

def process_multiple_devices(devices: List[DeviceInfo], username: str = "", password: str = "", 
                           expiry_days: int = 30, report_only: bool = False) -> BatchCleanupReport:
    """
    Process certificate cleanup for multiple F5 devices
    
    Args:
        devices: List of DeviceInfo objects
        username: Default username if not specified in CSV
        password: Default password if not specified in CSV  
        expiry_days: Days ahead to consider certificates as expiring
        report_only: Whether to only generate reports without cleanup
        
    Returns:
        BatchCleanupReport with results from all devices
    """
    reports = []
    successful_devices = 0
    failed_devices = 0
    
    print(f"🔄 Processing {len(devices)} F5 device(s)...")
    print("=" * 80)
    
    for i, device in enumerate(devices, 1):
        print(f"\n📟 Processing device {i}/{len(devices)}: {device.hostname} ({device.ip_address})")
        print("-" * 60)
        
        # Use device credentials if available, otherwise use provided defaults
        device_username = device.username or username
        device_password = device.password or password
        
        if not device_username or not device_password:
            print(f"❌ No credentials available for {device.hostname}")
            reports.append(CleanupReport(
                device_hostname=device.hostname,
                device_ip=device.ip_address,
                total_certificates=0,
                expired_certificates=[],
                expiring_certificates=[],
                unused_expired=[],
                used_expired=[],
                scan_timestamp=datetime.datetime.now(),
                connection_successful=False,
                error_message="Missing credentials"
            ))
            failed_devices += 1
            continue
        
        try:
            # Initialize F5 connection without testing (we'll handle errors gracefully)
            f5_cleanup = F5CertificateCleanup(
                device.ip_address, 
                device_username, 
                device_password, 
                expiry_days,
                test_connection=False
            )
            
            # Test connection manually to catch errors
            try:
                f5_cleanup._test_connection()
            except Exception as e:
                print(f"❌ Connection failed: {e}")
                reports.append(CleanupReport(
                    device_hostname=device.hostname,
                    device_ip=device.ip_address,
                    total_certificates=0,
                    expired_certificates=[],
                    expiring_certificates=[],
                    unused_expired=[],
                    used_expired=[],
                    scan_timestamp=datetime.datetime.now(),
                    connection_successful=False,
                    error_message=str(e)
                ))
                failed_devices += 1
                continue
            
            # Discover and analyze certificates
            certificates = f5_cleanup.discover_certificates()
            report = f5_cleanup.analyze_certificates(certificates)
            
            # Execute cleanup if not report-only mode
            if not report_only and (report.expired_certificates):
                if report.unused_expired or report.used_expired:
                    print(f"\n⚠️  Found {len(report.expired_certificates)} expired certificate(s) on {device.hostname}")
                    confirm = input(f"❓ Proceed with cleanup on {device.hostname}? (yes/no/skip): ").lower().strip()
                    
                    if confirm == 'yes':
                        stats = f5_cleanup.execute_cleanup(report)
                        print(f"✅ Cleanup completed on {device.hostname}")
                    elif confirm == 'skip':
                        print(f"⏭️  Skipping cleanup on {device.hostname}")
                    else:
                        print(f"❌ Cleanup cancelled for {device.hostname}")
            
            reports.append(report)
            successful_devices += 1
            
        except Exception as e:
            print(f"❌ Error processing {device.hostname}: {e}")
            reports.append(CleanupReport(
                device_hostname=device.hostname,
                device_ip=device.ip_address,
                total_certificates=0,
                expired_certificates=[],
                expiring_certificates=[],
                unused_expired=[],
                used_expired=[],
                scan_timestamp=datetime.datetime.now(),
                connection_successful=False,
                error_message=str(e)
            ))
            failed_devices += 1
    
    print("\n" + "=" * 80)
    print(f"📊 Batch Processing Summary:")
    print(f"  Total devices: {len(devices)}")
    print(f"  Successful: {successful_devices}")
    print(f"  Failed: {failed_devices}")
    
    return BatchCleanupReport(
        reports=reports,
        total_devices=len(devices),
        successful_devices=successful_devices,
        failed_devices=failed_devices,
        scan_timestamp=datetime.datetime.now()
    )

def generate_batch_html_report(batch_report: BatchCleanupReport, output_file: str = "f5_batch_cert_cleanup_report.html"):
    """
    Generate HTML report for batch certificate cleanup across multiple devices
    
    Args:
        batch_report: BatchCleanupReport object
        output_file: Output HTML file path
    """
    print(f"📄 Generating batch HTML report: {output_file}")
    
    # Calculate totals across all devices
    total_certs = sum(r.total_certificates for r in batch_report.reports if r.connection_successful)
    total_expired = sum(len(r.expired_certificates) for r in batch_report.reports if r.connection_successful)
    total_expiring = sum(len(r.expiring_certificates) for r in batch_report.reports if r.connection_successful)
    total_unused_expired = sum(len(r.unused_expired) for r in batch_report.reports if r.connection_successful)
    total_used_expired = sum(len(r.used_expired) for r in batch_report.reports if r.connection_successful)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>F5 Batch Certificate Cleanup Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #333; border-bottom: 2px solid #007acc; padding-bottom: 5px; }}
        .summary {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .device-section {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }}
        .device-header {{ background: #f8f9fa; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 5px 5px 0 0; }}
        .cert-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        .cert-table th, .cert-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 14px; }}
        .cert-table th {{ background-color: #007acc; color: white; }}
        .cert-table tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .success {{ background-color: #d4edda; }}
        .failure {{ background-color: #f8d7da; }}
        .warning {{ background-color: #fff3cd; }}
        .badge {{ padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; color: black; }}
        .timestamp {{ color: #666; font-style: italic; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #007acc; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🏢 F5 BIG-IP Batch Certificate Cleanup Report</h1>
        
        <div class="summary">
            <h3>📊 Overall Summary</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{batch_report.total_devices}</div>
                    <div>Total Devices</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{batch_report.successful_devices}</div>
                    <div>Successful Connections</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{batch_report.failed_devices}</div>
                    <div>Failed Connections</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_certs}</div>
                    <div>Total Certificates</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_expired}</div>
                    <div>Expired Certificates</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_unused_expired}</div>
                    <div>Safe to Delete</div>
                </div>
            </div>
            <p class="timestamp">Report generated: {batch_report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>📋 Device-by-Device Results</h2>
"""
    
    for report in batch_report.reports:
        if not report.connection_successful:
            html_content += f"""
        <div class="device-section failure">
            <div class="device-header">
                <h3>❌ {report.device_hostname} ({report.device_ip})</h3>
                <span class="badge badge-danger">Connection Failed</span>
            </div>
            <p><strong>Error:</strong> {report.error_message}</p>
        </div>
"""
        else:
            status_class = "success" if not report.expired_certificates else "warning"
            status_badge = "badge-success" if not report.expired_certificates else "badge-warning"
            status_text = "No Issues" if not report.expired_certificates else f"{len(report.expired_certificates)} Expired"
            
            html_content += f"""
        <div class="device-section {status_class}">
            <div class="device-header">
                <h3>🖥️ {report.device_hostname} ({report.device_ip})</h3>
                <span class="badge {status_badge}">{status_text}</span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{report.total_certificates}</div>
                    <div>Total Certificates</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(report.expired_certificates)}</div>
                    <div>Expired</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(report.expiring_certificates)}</div>
                    <div>Expiring Soon</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(report.unused_expired)}</div>
                    <div>Safe to Delete</div>
                </div>
            </div>
"""
            
            if report.expired_certificates:
                html_content += f"""
            <h4>⚠️ Expired Certificates ({len(report.expired_certificates)})</h4>
            <table class="cert-table">
                <thead>
                    <tr>
                        <th>Certificate Name</th>
                        <th>Expiration Date</th>
                        <th>Days Expired</th>
                        <th>Status</th>
                        <th>Usage Count</th>
                    </tr>
                </thead>
                <tbody>
"""
                
                for cert in report.expired_certificates:
                    is_unused = cert in report.unused_expired
                    usage_count = 0
                    for used_cert, usage_list in report.used_expired:
                        if used_cert.name == cert.name:
                            usage_count = len(usage_list)
                            break
                    
                    status = "Safe to Delete" if is_unused else f"Used by {usage_count} object(s)"
                    status_class = "badge-success" if is_unused else "badge-warning"
                    
                    html_content += f"""
                    <tr>
                        <td>{cert.name}</td>
                        <td>{cert.expiration_date.strftime('%Y-%m-%d')}</td>
                        <td>{abs(cert.days_until_expiry)}</td>
                        <td><span class="badge {status_class}">{status}</span></td>
                        <td>{usage_count}</td>
                    </tr>
"""
                
                html_content += """
                </tbody>
            </table>
"""
            
            html_content += """
        </div>
"""
    
    html_content += """
        
        <h2>🎯 Recommended Actions</h2>
        <ol>
            <li><strong>Address Failed Connections</strong> - Resolve connectivity and credential issues for failed devices</li>
            <li><strong>Review Device Reports</strong> - Each device section shows certificates needing attention</li>
            <li><strong>Prioritize by Usage</strong> - Focus on certificates used by multiple objects first</li>
            <li><strong>Plan Maintenance Windows</strong> - Schedule certificate cleanup during low-traffic periods</li>
            <li><strong>Coordinate Renewals</strong> - Plan proper certificate renewals for production services</li>
        </ol>
        
        <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-radius: 5px;">
            <h4>⚠️ Important Notes</h4>
            <ul>
                <li>This batch report covers multiple F5 devices - review each device carefully</li>
                <li>Connection failures may indicate network, credential, or device issues</li>
                <li>Certificate cleanup should be coordinated across all affected devices</li>
                <li>Always test certificate changes in non-production environments first</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Batch report saved to: {os.path.abspath(output_file)}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='F5 BIG-IP Certificate Cleanup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single device
  python f5_cert_cleanup.py --host 192.168.1.100 --username admin
  python f5_cert_cleanup.py --host mybigip.local --expiry-days 45 --report-only
  
  # Multiple devices from CSV
  python f5_cert_cleanup.py --devices-csv devices.csv --username admin
  python f5_cert_cleanup.py --devices-csv devices.csv --username admin --report-only
        """
    )
    
    # Device specification (either single host or CSV file)
    device_group = parser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--host', help='F5 BIG-IP hostname or IP address (single device mode)')
    device_group.add_argument('--devices-csv', help='CSV file containing device information (batch mode)')
    
    parser.add_argument('--username', help='F5 username (required for single device, optional for CSV if specified in file)')
    parser.add_argument('--password', help='F5 password (will prompt if not provided)')
    parser.add_argument('--expiry-days', type=int, default=30, 
                       help='Days ahead to consider certificates as expiring (default: 30)')
    parser.add_argument('--report-only', action='store_true', 
                       help='Generate report only, do not perform cleanup')
    parser.add_argument('--report-file', default='f5_cert_cleanup_report.html',
                       help='HTML report filename (default: f5_cert_cleanup_report.html)')
    parser.add_argument('--batch-report-file', default='f5_batch_cert_cleanup_report.html',
                       help='Batch HTML report filename for CSV mode (default: f5_batch_cert_cleanup_report.html)')
    
    args = parser.parse_args()
    
    # Validate arguments based on mode
    if args.host and not args.username:
        print("❌ --username is required when using --host")
        sys.exit(1)
    
    try:
        if args.devices_csv:
            # Batch processing mode
            print("🏢 Batch processing mode: Reading devices from CSV")
            
            devices = read_devices_csv(args.devices_csv)
            if not devices:
                print("❌ No valid devices found in CSV file")
                sys.exit(1)
            
            # Get default credentials if not specified in CSV
            default_username = args.username or ""
            default_password = args.password or ""
            
            if not default_username:
                default_username = input("Default username (if not in CSV): ").strip()
            
            if not default_password:
                default_password = getpass.getpass("Default password (if not in CSV): ")
            
            # Process multiple devices
            batch_report = process_multiple_devices(
                devices, 
                default_username, 
                default_password, 
                args.expiry_days, 
                args.report_only
            )
            
            # Generate batch HTML report
            generate_batch_html_report(batch_report, args.batch_report_file)
            
            # Print final summary
            print(f"\n🎉 Batch processing completed!")
            print(f"  📋 Total devices processed: {batch_report.total_devices}")
            print(f"  ✅ Successful connections: {batch_report.successful_devices}")
            print(f"  ❌ Failed connections: {batch_report.failed_devices}")
            
            total_expired = sum(len(r.expired_certificates) for r in batch_report.reports if r.connection_successful)
            total_safe_delete = sum(len(r.unused_expired) for r in batch_report.reports if r.connection_successful)
            
            print(f"  🔒 Total expired certificates found: {total_expired}")
            print(f"  🗑️  Total safe to delete: {total_safe_delete}")
            
        else:
            # Single device mode
            print("🖥️  Single device mode")
            
            # Get password if not provided
            if not args.password:
                args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
            
            # Initialize F5 connection
            f5_cleanup = F5CertificateCleanup(args.host, args.username, args.password, args.expiry_days)
            
            # Discover certificates
            certificates = f5_cleanup.discover_certificates()
            
            if not certificates:
                print("ℹ️  No certificates found on the F5 device")
                return
            
            # Analyze certificates
            report = f5_cleanup.analyze_certificates(certificates)
            
            # Generate HTML report (single device format)
            f5_cleanup.generate_html_report(report, args.report_file)
            
            # Print summary
            print(f"\n📊 Cleanup Summary:")
            print(f"  Total certificates: {report.total_certificates}")
            print(f"  Expired certificates: {len(report.expired_certificates)}")
            print(f"  Expiring soon: {len(report.expiring_certificates)}")
            print(f"  Safe to delete: {len(report.unused_expired)}")
            print(f"  Require dereferencing: {len(report.used_expired)}")
            
            if args.report_only:
                print(f"\n📄 Report-only mode: Review the generated report and run without --report-only to execute cleanup")
                return
            
            if not report.expired_certificates:
                print("\n✅ No expired certificates found - no cleanup needed!")
                return
            
            # Ask for user confirmation
            print(f"\n⚠️  This will delete {len(report.expired_certificates)} expired certificate(s)")
            print(f"   - {len(report.unused_expired)} will be deleted directly")
            print(f"   - {len(report.used_expired)} will be dereferenced first")
            
            confirm = input("\n❓ Do you want to proceed with the cleanup? (yes/no): ").lower().strip()
            
            if confirm != 'yes':
                print("❌ Cleanup cancelled by user")
                return
            
            # Execute cleanup
            stats = f5_cleanup.execute_cleanup(report)
            
            # Print final results
            print(f"\n🎉 Cleanup completed!")
            print(f"  ✅ Deleted unused certificates: {stats['deleted_unused']}")
            print(f"  ✅ Deleted used certificates: {stats['deleted_used']}")
            print(f"  🔄 Dereferenced objects: {stats['dereferenced']}")
            
            if stats['failed_dereference'] or stats['failed_delete']:
                print(f"  ❌ Failed dereferencing: {stats['failed_dereference']}")
                print(f"  ❌ Failed deletions: {stats['failed_delete']}")
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 