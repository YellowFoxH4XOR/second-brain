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
import ssl
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class F5TLSAdapter(HTTPAdapter):
    """
    Custom TLS adapter for F5 BIG-IP devices to handle different TLS versions
    
    F5 devices across different versions may require specific TLS versions:
    - Older devices (v11.x-v12.x): May require TLSv1.0/TLSv1.1 support
    - Newer devices (v13.x+): Typically use TLSv1.2/TLSv1.3
    - Some devices have specific cipher requirements
    """
    
    def __init__(self, tls_version=None, ciphers=None, **kwargs):
        """
        Initialize TLS adapter with specific TLS configuration
        
        Args:
            tls_version: Specific TLS version ('auto', 'tlsv1', 'tlsv1_1', 'tlsv1_2', 'tlsv1_3')
            ciphers: Custom cipher suite string
        """
        self.tls_version = tls_version or 'auto'
        self.ciphers = ciphers
        super().__init__(**kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        """Initialize pool manager with custom TLS context"""
        # Create custom SSL context
        context = create_urllib3_context()
        
        # Configure TLS version based on specified version
        if self.tls_version == 'auto':
            # Auto mode: try modern TLS first, fall back if needed
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            except AttributeError:
                # Fallback for older Python versions
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        
        elif self.tls_version == 'tlsv1':
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1
            except AttributeError:
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
        
        elif self.tls_version == 'tlsv1_1':
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1_1
                context.maximum_version = ssl.TLSVersion.TLSv1_1
            except AttributeError:
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2
        
        elif self.tls_version == 'tlsv1_2':
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            except AttributeError:
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        
        elif self.tls_version == 'tlsv1_3':
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            except AttributeError:
                # TLSv1.3 not available in older Python, fall back to TLSv1.2
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
        
        elif self.tls_version == 'legacy':
            # Legacy mode: support older TLS versions for old F5 devices
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            except AttributeError:
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        
        # Set custom ciphers if provided
        if self.ciphers:
            try:
                context.set_ciphers(self.ciphers)
            except Exception as e:
                print(f"⚠️  Warning: Failed to set custom ciphers: {e}")
        
        # Disable hostname verification for F5 devices (often use IP addresses)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def get_f5_compatible_session(tls_version='auto', ciphers=None, max_retries=3):
    """
    Create a requests session optimized for F5 BIG-IP devices
    
    Args:
        tls_version: TLS version strategy ('auto', 'legacy', 'tlsv1_2', etc.)
        ciphers: Custom cipher suite
        max_retries: Number of retry attempts
        
    Returns:
        Configured requests session
    """
    session = requests.Session()
    
    # Mount the custom TLS adapter
    adapter = F5TLSAdapter(
        tls_version=tls_version, 
        ciphers=ciphers,
        max_retries=max_retries
    )
    
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    
    # Set reasonable timeouts
    session.timeout = (10, 30)  # (connect_timeout, read_timeout)
    
    # Disable SSL verification (F5 devices often use self-signed certs)
    session.verify = False
    
    return session

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
    corresponding_key: str = ""  # Associated SSL key name
    partition: str = "Common"  # Partition where certificate resides

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
    protected_expired: List[CertificateInfo]  # Default certificates that are expired but protected
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
    
    def __init__(self, host: str, username: str, password: str, expiry_days: int = 30, 
                 test_connection: bool = True, tls_version: str = 'auto', ciphers: str = None,
                 use_bulk_optimization: bool = True):
        """
        Initialize F5 connection and configuration
        
        Args:
            host: F5 BIG-IP hostname or IP
            username: F5 username
            password: F5 password
            expiry_days: Days ahead to consider certificates as "expiring soon"
            test_connection: Whether to test connection during initialization
            tls_version: TLS version strategy ('auto', 'legacy', 'tlsv1_2', etc.)
            ciphers: Custom cipher suite string
            use_bulk_optimization: Whether to use bulk optimization for certificate usage checking
        """
        self.original_host = host
        self.host = host.rstrip('/')
        if not self.host.startswith('https://'):
            self.host = f"https://{self.host}"
        
        self.auth = (username, password)
        self.expiry_days = expiry_days
        self.tls_version = tls_version
        self.ciphers = ciphers
        self.use_bulk_optimization = use_bulk_optimization
        
        # Create session with TLS adapter
        self.session = self._create_f5_session()
        
        # Cache for module availability checks
        self._gtm_available = None
        self._apm_available = None
        
        # Test connection if requested
        if test_connection:
            try:
                self._test_connection()
            except Exception as e:
                # Try with legacy TLS if auto mode fails
                if self.tls_version == 'auto':
                    print(f"⚠️  Initial connection failed, trying legacy TLS mode...")
                    self.tls_version = 'legacy'
                    self.session = self._create_f5_session()
                    try:
                        self._test_connection()
                        print(f"✅ Connected using legacy TLS mode")
                    except Exception as e2:
                        print(f"❌ Failed to connect even with legacy TLS: {e2}")
                        sys.exit(1)
                else:
                    print(f"❌ Failed to connect to F5 device: {e}")
                    sys.exit(1)
    
    def _create_f5_session(self):
        """Create a session with F5-compatible TLS settings"""
        session = get_f5_compatible_session(
            tls_version=self.tls_version,
            ciphers=self.ciphers,
            max_retries=3
        )
        session.auth = self.auth
        return session
    
    def _test_connection(self):
        """Test F5 API connectivity"""
        response = self.session.get(f"{self.host}/mgmt/tm/sys/version")
        response.raise_for_status()
        print(f"✅ Connected to F5 BIG-IP: {self.host}")
    
    def discover_partitions(self) -> List[str]:
        """
        Discover all administrative partitions on the F5 device
        
        Returns:
            List of partition names
        """
        try:
            response = self._make_request('GET', '/mgmt/tm/auth/partition')
            partitions = []
            
            for partition_data in response.json().get('items', []):
                partitions.append(partition_data['name'])
            
            # Always include Common if not already in list
            if 'Common' not in partitions:
                partitions.insert(0, 'Common')
            
            print(f"🗂️  Found {len(partitions)} partition(s): {', '.join(partitions)}")
            return partitions
            
        except Exception as e:
            print(f"⚠️  Warning: Could not discover partitions, defaulting to Common only: {e}")
            return ['Common']
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make authenticated request to F5 API"""
        url = f"{self.host}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    
    def discover_ssl_keys(self, partitions: List[str]) -> Dict[str, str]:
        """
        Discover all SSL keys across all partitions on the F5 device
        
        Args:
            partitions: List of partition names to search
        
        Returns:
            Dictionary mapping key names to their full paths
        """
        keys = {}
        
        for partition in partitions:
            try:
                # Use partition filter in API call
                response = self._make_request('GET', f'/mgmt/tm/sys/file/ssl-key?$filter=partition eq {partition}')
                
                for key_data in response.json().get('items', []):
                    keys[key_data['name']] = key_data['fullPath']
                    
            except Exception as e:
                print(f"⚠️  Warning: Could not discover SSL keys in partition {partition}: {e}")
        
        # If partition filtering doesn't work, fall back to getting all keys
        if not keys:
            try:
                response = self._make_request('GET', '/mgmt/tm/sys/file/ssl-key')
                for key_data in response.json().get('items', []):
                    keys[key_data['name']] = key_data['fullPath']
            except Exception as e:
                print(f"⚠️  Warning: Could not discover SSL keys: {e}")
                return {}
        
        print(f"🔑 Found {len(keys)} SSL keys across all partitions")
        return keys
    
    def map_certificates_to_keys(self, certificates: List[CertificateInfo], keys: Dict[str, str]) -> List[CertificateInfo]:
        """
        Map certificates to their corresponding SSL keys
        
        Args:
            certificates: List of CertificateInfo objects
            keys: Dictionary of available SSL keys
            
        Returns:
            Updated list of CertificateInfo objects with corresponding keys
        """
        for cert in certificates:
            # Try to find corresponding key using common naming patterns
            cert_name = cert.name
            possible_key_names = [
                cert_name,  # Exact same name
                cert_name.replace('.crt', '.key'),  # Replace .crt with .key
                cert_name.replace('.pem', '.key'),  # Replace .pem with .key
                cert_name.replace('cert', 'key'),   # Replace 'cert' with 'key'
                cert_name.replace('certificate', 'key'),  # Replace 'certificate' with 'key'
                cert_name + '.key',  # Append .key
                cert_name.rsplit('.', 1)[0] + '.key' if '.' in cert_name else cert_name + '.key'  # Replace extension with .key
            ]
            
            # Find matching key
            for key_name in possible_key_names:
                if key_name in keys:
                    cert.corresponding_key = key_name
                    break
        
        # Report mapping results
        mapped_count = sum(1 for cert in certificates if cert.corresponding_key)
        print(f"🔗 Mapped {mapped_count}/{len(certificates)} certificates to SSL keys")
        
        return certificates
    
    def discover_certificates(self) -> List[CertificateInfo]:
        """
        Discover all SSL certificates across all partitions on the F5 device and map them to keys
        
        Returns:
            List of CertificateInfo objects with key mappings
        """
        print("🔍 Discovering SSL certificates across all partitions...")
        
        # First discover all partitions
        partitions = self.discover_partitions()
        certificates = []
        
        for partition in partitions:
            try:
                # Use partition filter in API call
                response = self._make_request('GET', f'/mgmt/tm/sys/file/ssl-cert?$filter=partition eq {partition}')
                partition_certs = 0
                
                for cert_data in response.json().get('items', []):
                    try:
                        # Parse expiration date
                        exp_timestamp = cert_data.get('expirationDate', 0)
                        exp_date = datetime.datetime.fromtimestamp(exp_timestamp)
                        
                        # Calculate days until expiry
                        now = datetime.datetime.now()
                        days_until_expiry = (exp_date - now).days
                        
                        # Extract partition from full path (e.g., /Common/cert.crt -> Common)
                        full_path = cert_data['fullPath']
                        cert_partition = full_path.split('/')[1] if full_path.startswith('/') and '/' in full_path[1:] else partition
                        
                        cert_info = CertificateInfo(
                            name=cert_data['name'],
                            full_path=full_path,
                            expiration_date=exp_date,
                            days_until_expiry=days_until_expiry,
                            is_expired=days_until_expiry < 0,
                            is_expiring_soon=0 <= days_until_expiry <= self.expiry_days,
                            subject=cert_data.get('subject', ''),
                            issuer=cert_data.get('issuer', ''),
                            partition=cert_partition
                        )
                        
                        certificates.append(cert_info)
                        partition_certs += 1
                        
                    except Exception as e:
                        print(f"⚠️  Warning: Could not process certificate {cert_data.get('name', 'unknown')} in partition {partition}: {e}")
                
                if partition_certs > 0:
                    print(f"  📁 Partition {partition}: {partition_certs} certificates")
                    
            except Exception as e:
                print(f"⚠️  Warning: Could not discover certificates in partition {partition}: {e}")
        
        # If partition filtering doesn't work, fall back to getting all certificates
        if not certificates:
            try:
                print("🔄 Falling back to discovery without partition filtering...")
                response = self._make_request('GET', '/mgmt/tm/sys/file/ssl-cert')
                
                for cert_data in response.json().get('items', []):
                    try:
                        # Parse expiration date
                        exp_timestamp = cert_data.get('expirationDate', 0)
                        exp_date = datetime.datetime.fromtimestamp(exp_timestamp)
                        
                        # Calculate days until expiry
                        now = datetime.datetime.now()
                        days_until_expiry = (exp_date - now).days
                        
                        # Extract partition from full path (e.g., /Common/cert.crt -> Common)
                        full_path = cert_data['fullPath']
                        cert_partition = full_path.split('/')[1] if full_path.startswith('/') and '/' in full_path[1:] else 'Common'
                        
                        cert_info = CertificateInfo(
                            name=cert_data['name'],
                            full_path=full_path,
                            expiration_date=exp_date,
                            days_until_expiry=days_until_expiry,
                            is_expired=days_until_expiry < 0,
                            is_expiring_soon=0 <= days_until_expiry <= self.expiry_days,
                            subject=cert_data.get('subject', ''),
                            issuer=cert_data.get('issuer', ''),
                            partition=cert_partition
                        )
                        
                        certificates.append(cert_info)
                        
                    except Exception as e:
                        print(f"⚠️  Warning: Could not process certificate {cert_data.get('name', 'unknown')}: {e}")
                        
            except Exception as e:
                print(f"❌ Failed to discover certificates: {e}")
                return []
        
        print(f"📋 Found {len(certificates)} total certificates across {len(partitions)} partitions")
        
        # Discover and map SSL keys
        keys = self.discover_ssl_keys(partitions)
        certificates = self.map_certificates_to_keys(certificates, keys)
        
        return certificates
    
    def check_certificate_usage(self, cert_path: str, partitions: List[str] = None) -> List[CertificateUsage]:
        """
        Check where a certificate is being used across F5 configuration in all partitions
        
        Args:
            cert_path: Full path of certificate (e.g., '/Common/cert.crt')
            partitions: List of partitions to search (if None, will discover automatically)
            
        Returns:
            List of CertificateUsage objects
        """
        usage_list = []
        
        # Get partitions if not provided
        if partitions is None:
            partitions = self.discover_partitions()
        
        # For each partition, check all object types for certificate usage
        for partition in partitions:
            self._check_partition_certificate_usage(cert_path, partition, usage_list)
        
        return usage_list
    
    def _check_partition_certificate_usage(self, cert_path: str, partition: str, usage_list: List[CertificateUsage]) -> None:
        """
        Check certificate usage within a specific partition
        
        Args:
            cert_path: Full path of certificate
            partition: Partition name to check
            usage_list: List to append usage results to
        """
        
        # Check Client-SSL profiles
        try:
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/client-ssl?$filter=partition eq {partition}')
            for profile in response.json().get('items', []):
                cert_key_chain = profile.get('certKeyChain', [])
                for chain in cert_key_chain:
                    if chain.get('cert') == cert_path:
                        usage_list.append(CertificateUsage(
                            object_type='Client-SSL Profile',
                            object_name=profile['name'],
                            object_path=profile['fullPath'],
                            field_name='certKeyChain.cert',
                            partition=partition
                        ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Client-SSL profiles in partition {partition}: {e}")
        
        # Check Server-SSL profiles
        try:
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/server-ssl?$filter=partition eq {partition}')
            for profile in response.json().get('items', []):
                if profile.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Server-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='cert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Server-SSL profiles in partition {partition}: {e}")
        
        # Check LTM HTTPS monitors
        try:
            response = self._make_request('GET', f'/mgmt/tm/ltm/monitor/https?$filter=partition eq {partition}')
            for monitor in response.json().get('items', []):
                if monitor.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='LTM HTTPS Monitor',
                        object_name=monitor['name'],
                        object_path=monitor['fullPath'],
                        field_name='cert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check LTM HTTPS monitors in partition {partition}: {e}")
        
        # Check GTM HTTPS monitors (only if GTM is available)
        if self.is_gtm_available():
            try:
                response = self._make_request('GET', f'/mgmt/tm/gtm/monitor/https?$filter=partition eq {partition}')
                for monitor in response.json().get('items', []):
                    if monitor.get('cert') == cert_path:
                        usage_list.append(CertificateUsage(
                            object_type='GTM HTTPS Monitor',
                            object_name=monitor['name'],
                            object_path=monitor['fullPath'],
                            field_name='cert',
                            partition=partition
                        ))
            except Exception as e:
                print(f"⚠️  Warning: Could not check GTM HTTPS monitors in partition {partition}: {e}")
        
        # Check OCSP responders
        try:
            response = self._make_request('GET', f'/mgmt/tm/sys/crypto/cert-validator/ocsp?$filter=partition eq {partition}')
            for ocsp in response.json().get('items', []):
                trusted_responders = ocsp.get('trustedResponders', [])
                if isinstance(trusted_responders, list):
                    for responder in trusted_responders:
                        if responder == cert_path:
                            usage_list.append(CertificateUsage(
                                object_type='OCSP Responder',
                                object_name=ocsp['name'],
                                object_path=ocsp['fullPath'],
                                field_name='trustedResponders',
                                partition=partition
                            ))
                elif trusted_responders == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='OCSP Responder',
                        object_name=ocsp['name'],
                        object_path=ocsp['fullPath'],
                        field_name='trustedResponders',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check OCSP responders in partition {partition}: {e}")
        
        # Check APM authentication profiles (only if APM is available)
        if self.is_apm_available():
            try:
                response = self._make_request('GET', f'/mgmt/tm/apm/profile/authentication?$filter=partition eq {partition}')
                for auth_profile in response.json().get('items', []):
                    if auth_profile.get('cert') == cert_path:
                        usage_list.append(CertificateUsage(
                            object_type='APM Authentication Profile',
                            object_name=auth_profile['name'],
                            object_path=auth_profile['fullPath'],
                            field_name='cert',
                            partition=partition
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
                                    field_name='trustedCAs',
                                    partition=partition
                                ))
                    elif trusted_cas == cert_path:
                        usage_list.append(CertificateUsage(
                            object_type='APM Authentication Profile',
                            object_name=auth_profile['name'],
                            object_path=auth_profile['fullPath'],
                            field_name='trustedCAs',
                            partition=partition
                        ))
            except Exception as e:
                print(f"⚠️  Warning: Could not check APM authentication profiles in partition {partition}: {e}")
        
        # Check LDAP servers
        try:
            response = self._make_request('GET', f'/mgmt/tm/auth/ldap?$filter=partition eq {partition}')
            for ldap in response.json().get('items', []):
                if ldap.get('sslCaCertFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='LDAP Server',
                        object_name=ldap['name'],
                        object_path=ldap['fullPath'],
                        field_name='sslCaCertFile',
                        partition=partition
                    ))
                if ldap.get('sslClientCert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='LDAP Server',
                        object_name=ldap['name'],
                        object_path=ldap['fullPath'],
                        field_name='sslClientCert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check LDAP servers in partition {partition}: {e}")
        
        # Check RADIUS servers
        try:
            response = self._make_request('GET', f'/mgmt/tm/auth/radius-server?$filter=partition eq {partition}')
            for radius in response.json().get('items', []):
                server_config = radius.get('server', {})
                if server_config.get('sslCaCertFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='RADIUS Server',
                        object_name=radius['name'],
                        object_path=radius['fullPath'],
                        field_name='server.sslCaCertFile',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check RADIUS servers in partition {partition}: {e}")
        
        # Check Syslog destinations (usually global, but check per partition)
        try:
            response = self._make_request('GET', f'/mgmt/tm/sys/syslog?$filter=partition eq {partition}')
            for syslog in response.json().get('items', []):
                remote_syslog = syslog.get('remotesyslog', {})
                if remote_syslog.get('cert') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Syslog Destination',
                        object_name=syslog.get('name', 'syslog'),
                        object_path=syslog.get('fullPath', f'/{partition}/syslog'),
                        field_name='remotesyslog.cert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Syslog destinations in partition {partition}: {e}")
    
    def analyze_certificates(self, certificates: List[CertificateInfo]) -> CleanupReport:
        """
        Analyze certificates for expiry and usage across all partitions
        
        Args:
            certificates: List of discovered certificates
            
        Returns:
            CleanupReport with analysis results
        """
        print("🔬 Analyzing certificate usage across all partitions...")
        
        # Discover partitions for usage checking
        partitions = self.discover_partitions()
        
        expired_certs = [cert for cert in certificates if cert.is_expired]
        expiring_certs = [cert for cert in certificates if cert.is_expiring_soon]
        
        unused_expired = []
        used_expired = []
        protected_expired = []
        
        # Filter out default certificates first (they are protected)
        non_protected_expired = []
        for cert in expired_certs:
            if self.is_default_certificate(cert.name, cert.full_path):
                protected_expired.append(cert)
                print(f"  🛡️  Default certificate protected from deletion: {cert.name} (partition: {cert.partition})")
            else:
                non_protected_expired.append(cert)
        
        # Only check usage for non-protected expired certificates
        if non_protected_expired:
            if self.use_bulk_optimization:
                print(f"🚀 Using bulk optimization for {len(non_protected_expired)} non-protected expired certificates...")
                usage_map = self.check_certificate_usage_bulk(non_protected_expired, partitions)
                
                # Process results
                for cert in non_protected_expired:
                    usage = usage_map.get(cert.full_path, [])
                    if not usage:
                        unused_expired.append(cert)
                        print(f"  ✅ {cert.name} - Not in use (safe to delete)")
                    else:
                        used_expired.append((cert, usage))
                        print(f"  ⚠️  {cert.name} - In use by {len(usage)} object(s)")
            else:
                print(f"📋 Using individual certificate checking for {len(non_protected_expired)} certificates...")
                for cert in non_protected_expired:
                    print(f"  📋 Checking usage for: {cert.name} (partition: {cert.partition})")
                    usage = self.check_certificate_usage(cert.full_path, partitions)
                    
                    if not usage:
                        unused_expired.append(cert)
                        print(f"    ✅ Not in use - safe to delete")
                    else:
                        used_expired.append((cert, usage))
                        print(f"    ⚠️  In use by {len(usage)} object(s) across partitions")
        else:
            print("ℹ️  No non-protected expired certificates to check")
        
        return CleanupReport(
            device_hostname=self.original_host,
            device_ip=self.host,
            total_certificates=len(certificates),
            expired_certificates=expired_certs,
            expiring_certificates=expiring_certs,
            unused_expired=unused_expired,
            used_expired=used_expired,
            protected_expired=protected_expired,
            scan_timestamp=datetime.datetime.now()
        )
    
    def generate_html_report(self, report: CleanupReport, output_file: str = None):
        """
        Generate HTML report for pre-deletion verification
        
        Args:
            report: CleanupReport object
            output_file: Output HTML file path (auto-generated if None)
        """
        # Auto-generate filename with device IP if not provided
        if output_file is None:
            # Extract IP from device_ip field or original_host
            device_ip = report.device_ip.replace('https://', '').replace('http://', '').split(':')[0]
            # Replace dots and colons with underscores for filename
            safe_ip = device_ip.replace('.', '_').replace(':', '_')
            output_file = f"f5_cert_cleanup_report_{safe_ip}.html"
        
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
            <p><strong>Device:</strong> {report.device_hostname} ({report.device_ip.replace('https://', '').replace('http://', '')})</p>
            <ul>
                <li><strong>Total Certificates:</strong> {report.total_certificates}</li>
                <li><strong>Expired Certificates:</strong> {len(report.expired_certificates)}</li>
 
                <li><strong>Safe to Delete (unused expired):</strong> {len(report.unused_expired)}</li>
                <li><strong>Require Dereferencing (used expired):</strong> {len(report.used_expired)}</li>
                <li><strong>Protected from Deletion (default certificates):</strong> {len(report.protected_expired)}</li>
            </ul>
            <p class="timestamp">Report generated: {report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>🗑️ Certificates Safe for Direct Deletion</h2>
        <p>These expired certificates are not referenced by any F5 objects and can be safely deleted:</p>
        <table class="cert-table">
            <thead>
                <tr>
                    <th>Certificate Name</th>
                    <th>Partition</th>
                    <th>Corresponding Key</th>
                    <th>Expiration Date</th>
                    <th>Days Expired</th>
                    <th>Subject</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for cert in report.unused_expired:
            key_info = cert.corresponding_key if cert.corresponding_key else "❌ No key found"
            html_content += f"""
                <tr class="safe-delete">
                    <td>{cert.name}</td>
                    <td>{cert.partition}</td>
                    <td>{key_info}</td>
                    <td>{cert.expiration_date.strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{abs(cert.days_until_expiry)}</td>
                    <td>{cert.subject}</td>
                    <td><span class="badge badge-success">Safe Delete</span></td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2>🛡️ Protected Certificates (Default)</h2>
        <p>These expired default certificates are protected from deletion and shown for informational purposes only:</p>
        <table class="cert-table">
            <thead>
                <tr>
                    <th>Certificate Name</th>
                    <th>Partition</th>
                    <th>Corresponding Key</th>
                    <th>Expiration Date</th>
                    <th>Days Expired</th>
                    <th>Subject</th>
                    <th>Protection Status</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for cert in report.protected_expired:
            key_info = cert.corresponding_key if cert.corresponding_key else "❌ No key found"
            html_content += f"""
                <tr style="background-color: #e1f5fe !important;">
                    <td>{cert.name}</td>
                    <td>{cert.partition}</td>
                    <td>{key_info}</td>
                    <td>{cert.expiration_date.strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{abs(cert.days_until_expiry)}</td>
                    <td>{cert.subject}</td>
                    <td><span class="badge" style="background: #1976d2; color: white;">Protected</span></td>
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
            <h4>📋 {cert.name} (Partition: {cert.partition})</h4>
            <p><strong>Expiration:</strong> {cert.expiration_date.strftime('%Y-%m-%d %H:%M:%S')} 
               ({abs(cert.days_until_expiry)} days expired)</p>
            <p><strong>Subject:</strong> {cert.subject}</p>
            <p><strong>Corresponding Key:</strong> {cert.corresponding_key if cert.corresponding_key else "❌ No key found"}</p>
            <p><strong>Used by {len(usage_list)} object(s) across partitions:</strong></p>
            <ul>
"""
            for usage in usage_list:
                html_content += f"""
                <li><strong>{usage.object_type}:</strong> {usage.object_name} (field: {usage.field_name}, partition: {usage.partition})</li>
"""
            html_content += """
            </ul>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Report saved to: {os.path.abspath(output_file)}")
    
    def create_certificate_backup(self, certificates: List[CertificateInfo], used_certificates: List[Tuple[CertificateInfo, List[CertificateUsage]]], backup_file: str = None):
        """
        Create a JSON backup of certificates before deletion for recovery purposes
        
        Args:
            certificates: List of all certificates being deleted
            used_certificates: List of certificates with their usage information
            backup_file: Backup file path (auto-generated if None)
        """
        # Auto-generate backup filename with device IP if not provided
        if backup_file is None:
            # Extract IP from host
            device_ip = self.host.replace('https://', '').replace('http://', '').split(':')[0]
            # Replace dots and colons with underscores for filename
            safe_ip = device_ip.replace('.', '_').replace(':', '_')
            backup_file = f"backup_{safe_ip}.json"
        
        print(f"💾 Creating certificate backup: {backup_file}")
        
        backup_data = {
            "backup_metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "device_host": self.original_host,
                "device_ip": self.host,
                "script_version": "1.0",
                "backup_type": "certificate_cleanup",
                "total_certificates": len(certificates),
                "total_used_certificates": len(used_certificates)
            },
            "certificates": [],
            "usage_information": []
        }
        
        # Backup certificate details
        for cert in certificates:
            cert_backup = {
                "name": cert.name,
                "full_path": cert.full_path,
                "partition": cert.partition,
                "expiration_date": cert.expiration_date.isoformat(),
                "days_until_expiry": cert.days_until_expiry,
                "is_expired": cert.is_expired,
                "is_expiring_soon": cert.is_expiring_soon,
                "subject": cert.subject,
                "issuer": cert.issuer,
                "corresponding_key": cert.corresponding_key
            }
            backup_data["certificates"].append(cert_backup)
        
        # Backup usage information for used certificates
        for cert, usage_list in used_certificates:
            usage_backup = {
                "certificate": {
                    "name": cert.name,
                    "full_path": cert.full_path,
                    "partition": cert.partition
                },
                "usage_locations": []
            }
            
            for usage in usage_list:
                usage_backup["usage_locations"].append({
                    "object_type": usage.object_type,
                    "object_name": usage.object_name,
                    "object_path": usage.object_path,
                    "field_name": usage.field_name,
                    "partition": usage.partition
                })
            
            backup_data["usage_information"].append(usage_backup)
        
        # Save backup to JSON file
        try:
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Certificate backup saved to: {os.path.abspath(backup_file)}")
            print(f"   📁 Backup contains {len(certificates)} certificate(s) and {len(used_certificates)} usage record(s)")
            
        except Exception as e:
            print(f"❌ Failed to create backup file: {e}")
    
    def get_default_certificate_for_partition(self, partition: str) -> Tuple[str, str]:
        """
        Get the appropriate default certificate and key for a partition
        
        Args:
            partition: Partition name
            
        Returns:
            Tuple of (default_cert_path, default_key_path)
        """
        # Check if partition has its own default certificate
        partition_default_cert = f"/{partition}/default.crt"
        partition_default_key = f"/{partition}/default.key"
        
        try:
            # Try to verify partition-specific default certificate exists
            encoded_name = partition_default_cert.replace('/', '~')
            self._make_request('GET', f"/mgmt/tm/sys/file/ssl-cert/{encoded_name}")
            return partition_default_cert, partition_default_key
        except:
            # Fall back to Common default
            return "/Common/default.crt", "/Common/default.key"
    
    def dereference_certificate(self, cert_path: str, usage: CertificateUsage) -> bool:
        """
        Dereference a certificate from an F5 object and replace with appropriate default for the partition
        
        Args:
            cert_path: Full path of certificate to dereference
            usage: CertificateUsage object describing where it's used
            
        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"  🔄 Dereferencing from {usage.object_type}: {usage.object_name} (partition: {usage.partition})")
            
            # Get appropriate default certificate for this partition
            default_cert, default_key = self.get_default_certificate_for_partition(usage.partition)
            print(f"    Using default certificate: {default_cert}")
            
            if usage.object_type == 'Client-SSL Profile':
                # Replace in Client-SSL profile
                update_data = {
                    "certKeyChain": [
                        {
                            "name": "default",
                            "cert": default_cert,
                            "key": default_key
                        }
                    ]
                }
                endpoint = f"/mgmt/tm/ltm/profile/client-ssl/{usage.object_name.replace('/', '~')}"
                
            elif usage.object_type == 'Server-SSL Profile':
                # Replace in Server-SSL profile
                update_data = {
                    "cert": default_cert,
                    "key": default_key
                }
                endpoint = f"/mgmt/tm/ltm/profile/server-ssl/{usage.object_name.replace('/', '~')}"
                
            elif usage.object_type in ['LTM HTTPS Monitor', 'GTM HTTPS Monitor']:
                # Replace in monitor
                update_data = {
                    "cert": default_cert
                }
                if 'LTM' in usage.object_type:
                    endpoint = f"/mgmt/tm/ltm/monitor/https/{usage.object_name.replace('/', '~')}"
                else:
                    endpoint = f"/mgmt/tm/gtm/monitor/https/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'OCSP Responder':
                # Replace in OCSP responder
                update_data = {
                    "trustedResponders": [default_cert]
                }
                endpoint = f"/mgmt/tm/sys/crypto/cert-validator/ocsp/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'APM Authentication Profile':
                # Replace in APM authentication profile
                if usage.field_name == 'cert':
                    update_data = {
                        "cert": default_cert
                    }
                elif usage.field_name == 'trustedCAs':
                    update_data = {
                        "trustedCAs": [default_cert]
                    }
                endpoint = f"/mgmt/tm/apm/profile/authentication/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'LDAP Server':
                # Replace in LDAP server
                if usage.field_name == 'sslCaCertFile':
                    update_data = {
                        "sslCaCertFile": default_cert
                    }
                elif usage.field_name == 'sslClientCert':
                    update_data = {
                        "sslClientCert": default_cert
                    }
                endpoint = f"/mgmt/tm/auth/ldap/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'RADIUS Server':
                # Replace in RADIUS server
                update_data = {
                    "server": {
                        "sslCaCertFile": default_cert
                    }
                }
                endpoint = f"/mgmt/tm/auth/radius-server/{usage.object_name.replace('/', '~')}"
            
            elif usage.object_type == 'Syslog Destination':
                # Replace in Syslog destination
                update_data = {
                    "remotesyslog": {
                        "cert": default_cert
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
    
    def delete_ssl_key(self, key_name: str) -> bool:
        """
        Delete an SSL key from F5
        
        Args:
            key_name: Name of SSL key to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # URL encode the key name
            encoded_name = key_name.replace('/', '~')
            endpoint = f"/mgmt/tm/sys/file/ssl-key/{encoded_name}"
            
            response = self._make_request('DELETE', endpoint)
            print(f"  🔑 Deleted SSL key: {key_name}")
            return True
            
        except Exception as e:
            print(f"  ❌ Failed to delete SSL key {key_name}: {e}")
            return False
    
    def delete_certificate(self, cert_name: str, key_name: str = "") -> Tuple[bool, bool]:
        """
        Delete a certificate and its corresponding SSL key from F5
        
        Args:
            cert_name: Name of certificate to delete
            key_name: Name of corresponding SSL key to delete (optional)
            
        Returns:
            Tuple of (cert_deleted, key_deleted) success flags
        """
        cert_deleted = False
        key_deleted = False
        
        # Safety check: Never delete default certificates
        if self.is_default_certificate(cert_name, cert_name):
            print(f"  🛡️  PROTECTED: Refusing to delete default certificate: {cert_name}")
            return False, False
        
        # Delete certificate
        try:
            # URL encode the certificate name
            encoded_name = cert_name.replace('/', '~')
            endpoint = f"/mgmt/tm/sys/file/ssl-cert/{encoded_name}"
            
            response = self._make_request('DELETE', endpoint)
            print(f"  ✅ Deleted certificate: {cert_name}")
            cert_deleted = True
            
        except Exception as e:
            print(f"  ❌ Failed to delete certificate {cert_name}: {e}")
        
        # Delete corresponding SSL key if provided
        if key_name:
            # Safety check for keys too
            if self.is_default_certificate(key_name, key_name):
                print(f"  🛡️  PROTECTED: Refusing to delete default key: {key_name}")
                key_deleted = True  # Consider successful to avoid error state
            else:
                try:
                    key_deleted = self.delete_ssl_key(key_name)
                except Exception as e:
                    print(f"  ❌ Failed to delete SSL key {key_name}: {e}")
        else:
            key_deleted = True  # No key to delete, consider successful
        
        return cert_deleted, key_deleted
    
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
            'deleted_keys': 0,
            'dereferenced': 0,
            'failed_dereference': 0,
            'failed_delete': 0,
            'failed_key_delete': 0
        }
        
        print("\n🧹 Starting certificate cleanup...")
        
        # Create backup before any deletion
        if report.expired_certificates:
            all_expired_certs = report.unused_expired + [cert for cert, _ in report.used_expired]
            self.create_certificate_backup(all_expired_certs, report.used_expired)
        
        # Delete unused expired certificates directly
        if report.unused_expired:
            print(f"\n🗑️  Deleting {len(report.unused_expired)} unused expired certificates...")
            for cert in report.unused_expired:
                cert_deleted, key_deleted = self.delete_certificate(cert.name, cert.corresponding_key)
                if cert_deleted:
                    stats['deleted_unused'] += 1
                    if cert.corresponding_key and key_deleted:
                        stats['deleted_keys'] += 1
                    elif cert.corresponding_key and not key_deleted:
                        stats['failed_key_delete'] += 1
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
                    cert_deleted, key_deleted = self.delete_certificate(cert.name, cert.corresponding_key)
                    if cert_deleted:
                        stats['deleted_used'] += 1
                        if cert.corresponding_key and key_deleted:
                            stats['deleted_keys'] += 1
                        elif cert.corresponding_key and not key_deleted:
                            stats['failed_key_delete'] += 1
                    else:
                        stats['failed_delete'] += 1
                else:
                    print(f"  ⚠️  Skipping deletion due to failed dereferencing")
        
        return stats
    
    def is_gtm_available(self) -> bool:
        """
        Check if GTM (Global Traffic Manager) module is available and licensed
        
        Returns:
            True if GTM is available, False otherwise
        """
        if self._gtm_available is not None:
            return self._gtm_available
        
        try:
            # Check if GTM module is provisioned
            response = self._make_request('GET', '/mgmt/tm/sys/provision')
            
            for module in response.json().get('items', []):
                if module.get('name') == 'gtm' and module.get('level') not in ['none', 'disabled']:
                    self._gtm_available = True
                    print(f"✅ GTM module is active (level: {module.get('level')})")
                    return True
            
            self._gtm_available = False
            print(f"ℹ️  GTM module is not active - skipping GTM checks")
            return False
            
        except Exception as e:
            print(f"⚠️  Warning: Could not check GTM module status: {e}")
            self._gtm_available = False
            return False
    
    def is_apm_available(self) -> bool:
        """
        Check if APM (Access Policy Manager) module is available and licensed
        
        Returns:
            True if APM is available, False otherwise
        """
        if self._apm_available is not None:
            return self._apm_available
        
        try:
            # Check if APM module is provisioned
            response = self._make_request('GET', '/mgmt/tm/sys/provision')
            
            for module in response.json().get('items', []):
                if module.get('name') == 'apm' and module.get('level') not in ['none', 'disabled']:
                    self._apm_available = True
                    print(f"✅ APM module is active (level: {module.get('level')})")
                    return True
            
            self._apm_available = False
            print(f"ℹ️  APM module is not active - skipping APM checks")
            return False
            
        except Exception as e:
            print(f"⚠️  Warning: Could not check APM module status: {e}")
            self._apm_available = False
            return False
    
    def is_default_certificate(self, cert_name: str, cert_path: str) -> bool:
        """
        Check if a certificate is a default certificate that should never be deleted
        
        Args:
            cert_name: Certificate name
            cert_path: Certificate full path
            
        Returns:
            True if this is a default certificate, False otherwise
        """
        # Check for default certificate patterns
        default_patterns = [
            'default.crt',
            'default.key',
            '/Common/default.crt',
            '/Common/default.key'
        ]
        
        # Check exact matches
        if cert_name in default_patterns or cert_path in default_patterns:
            return True
        
        # Check if name ends with default.crt or default.key
        if cert_name.endswith('default.crt') or cert_name.endswith('default.key'):
            return True
        
        # Check if path contains default certificate patterns
        if any(pattern in cert_path for pattern in default_patterns):
            return True
        
        return False
    
    def check_certificate_usage_bulk(self, certificates: List[CertificateInfo], partitions: List[str] = None) -> Dict[str, List[CertificateUsage]]:
        """
        Optimized bulk check for certificate usage across F5 configuration in all partitions
        This method fetches all objects once and checks all certificates in memory for better performance
        
        Args:
            certificates: List of CertificateInfo objects to check
            partitions: List of partitions to search (if None, will discover automatically)
            
        Returns:
            Dictionary mapping certificate full_path to list of CertificateUsage objects
        """
        print("🚀 Starting optimized bulk certificate usage analysis...")
        
        # Get partitions if not provided
        if partitions is None:
            partitions = self.discover_partitions()
        
        # Create mapping of certificate paths for quick lookup
        cert_paths = {cert.full_path for cert in certificates}
        usage_map = {cert.full_path: [] for cert in certificates}
        
        # Check module availability once (cached)
        gtm_available = self.is_gtm_available()
        apm_available = self.is_apm_available()
        
        # Calculate estimated API calls for performance comparison
        object_types_per_partition = 6  # Base object types (Client-SSL, Server-SSL, LTM HTTPS, OCSP, LDAP, RADIUS, Syslog)
        if gtm_available:
            object_types_per_partition += 1  # GTM HTTPS monitors
        if apm_available:
            object_types_per_partition += 1  # APM authentication profiles
        
        # Old method: certificates × partitions × object_types API calls
        old_api_calls = len(certificates) * len(partitions) * object_types_per_partition
        # New method: partitions × object_types API calls  
        new_api_calls = len(partitions) * object_types_per_partition
        
        if old_api_calls > 0:
            performance_improvement = (old_api_calls - new_api_calls) / old_api_calls * 100
            print(f"⚡ Performance: {new_api_calls} API calls vs {old_api_calls} individual calls ({performance_improvement:.1f}% reduction)")
        
        print(f"📊 Checking {len(certificates)} certificates across {len(partitions)} partition(s)")
        
        # Process each partition
        for partition_idx, partition in enumerate(partitions, 1):
            print(f"  📁 Processing partition {partition_idx}/{len(partitions)}: {partition}")
            
            # Fetch all objects of each type for this partition in bulk
            self._bulk_check_partition_objects(partition, cert_paths, usage_map, gtm_available, apm_available)
        
        print(f"✅ Bulk usage analysis completed")
        return usage_map
    
    def _bulk_check_partition_objects(self, partition: str, cert_paths: set, usage_map: Dict[str, List[CertificateUsage]], 
                                    gtm_available: bool, apm_available: bool) -> None:
        """
        Bulk check all object types in a partition for certificate usage
        
        Args:
            partition: Partition name to check
            cert_paths: Set of certificate paths to look for
            usage_map: Dictionary to update with usage results
            gtm_available: Whether GTM module is available
            apm_available: Whether APM module is available
        """
        
        # Check Client-SSL profiles
        try:
            print(f"    🔍 Checking Client-SSL profiles...")
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/client-ssl?$filter=partition eq {partition}')
            for profile in response.json().get('items', []):
                cert_key_chain = profile.get('certKeyChain', [])
                for chain in cert_key_chain:
                    cert_path = chain.get('cert')
                    if cert_path in cert_paths:
                        usage_map[cert_path].append(CertificateUsage(
                            object_type='Client-SSL Profile',
                            object_name=profile['name'],
                            object_path=profile['fullPath'],
                            field_name='certKeyChain.cert',
                            partition=partition
                        ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check Client-SSL profiles in partition {partition}: {e}")
        
        # Check Server-SSL profiles
        try:
            print(f"    🔍 Checking Server-SSL profiles...")
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/server-ssl?$filter=partition eq {partition}')
            for profile in response.json().get('items', []):
                cert_path = profile.get('cert')
                if cert_path in cert_paths:
                    usage_map[cert_path].append(CertificateUsage(
                        object_type='Server-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='cert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check Server-SSL profiles in partition {partition}: {e}")
        
        # Check LTM HTTPS monitors
        try:
            print(f"    🔍 Checking LTM HTTPS monitors...")
            response = self._make_request('GET', f'/mgmt/tm/ltm/monitor/https?$filter=partition eq {partition}')
            for monitor in response.json().get('items', []):
                cert_path = monitor.get('cert')
                if cert_path in cert_paths:
                    usage_map[cert_path].append(CertificateUsage(
                        object_type='LTM HTTPS Monitor',
                        object_name=monitor['name'],
                        object_path=monitor['fullPath'],
                        field_name='cert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check LTM HTTPS monitors in partition {partition}: {e}")
        
        # Check GTM HTTPS monitors (only if GTM is available)
        if gtm_available:
            try:
                print(f"    🔍 Checking GTM HTTPS monitors...")
                response = self._make_request('GET', f'/mgmt/tm/gtm/monitor/https?$filter=partition eq {partition}')
                for monitor in response.json().get('items', []):
                    cert_path = monitor.get('cert')
                    if cert_path in cert_paths:
                        usage_map[cert_path].append(CertificateUsage(
                            object_type='GTM HTTPS Monitor',
                            object_name=monitor['name'],
                            object_path=monitor['fullPath'],
                            field_name='cert',
                            partition=partition
                        ))
            except Exception as e:
                print(f"    ⚠️  Warning: Could not check GTM HTTPS monitors in partition {partition}: {e}")
        
        # Check OCSP responders
        try:
            print(f"    🔍 Checking OCSP responders...")
            response = self._make_request('GET', f'/mgmt/tm/sys/crypto/cert-validator/ocsp?$filter=partition eq {partition}')
            for ocsp in response.json().get('items', []):
                trusted_responders = ocsp.get('trustedResponders', [])
                if isinstance(trusted_responders, list):
                    for responder in trusted_responders:
                        if responder in cert_paths:
                            usage_map[responder].append(CertificateUsage(
                                object_type='OCSP Responder',
                                object_name=ocsp['name'],
                                object_path=ocsp['fullPath'],
                                field_name='trustedResponders',
                                partition=partition
                            ))
                elif trusted_responders in cert_paths:
                    usage_map[trusted_responders].append(CertificateUsage(
                        object_type='OCSP Responder',
                        object_name=ocsp['name'],
                        object_path=ocsp['fullPath'],
                        field_name='trustedResponders',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check OCSP responders in partition {partition}: {e}")
        
        # Check APM authentication profiles (only if APM is available)
        if apm_available:
            try:
                print(f"    🔍 Checking APM authentication profiles...")
                response = self._make_request('GET', f'/mgmt/tm/apm/profile/authentication?$filter=partition eq {partition}')
                for auth_profile in response.json().get('items', []):
                    # Check cert field
                    cert_path = auth_profile.get('cert')
                    if cert_path in cert_paths:
                        usage_map[cert_path].append(CertificateUsage(
                            object_type='APM Authentication Profile',
                            object_name=auth_profile['name'],
                            object_path=auth_profile['fullPath'],
                            field_name='cert',
                            partition=partition
                        ))
                    
                    # Check trustedCAs field (can be array or single value)
                    trusted_cas = auth_profile.get('trustedCAs', [])
                    if isinstance(trusted_cas, list):
                        for ca in trusted_cas:
                            if ca in cert_paths:
                                usage_map[ca].append(CertificateUsage(
                                    object_type='APM Authentication Profile',
                                    object_name=auth_profile['name'],
                                    object_path=auth_profile['fullPath'],
                                    field_name='trustedCAs',
                                    partition=partition
                                ))
                    elif trusted_cas in cert_paths:
                        usage_map[trusted_cas].append(CertificateUsage(
                            object_type='APM Authentication Profile',
                            object_name=auth_profile['name'],
                            object_path=auth_profile['fullPath'],
                            field_name='trustedCAs',
                            partition=partition
                        ))
            except Exception as e:
                print(f"    ⚠️  Warning: Could not check APM authentication profiles in partition {partition}: {e}")
        
        # Check LDAP servers
        try:
            print(f"    🔍 Checking LDAP servers...")
            response = self._make_request('GET', f'/mgmt/tm/auth/ldap?$filter=partition eq {partition}')
            for ldap in response.json().get('items', []):
                # Check sslCaCertFile
                cert_path = ldap.get('sslCaCertFile')
                if cert_path in cert_paths:
                    usage_map[cert_path].append(CertificateUsage(
                        object_type='LDAP Server',
                        object_name=ldap['name'],
                        object_path=ldap['fullPath'],
                        field_name='sslCaCertFile',
                        partition=partition
                    ))
                # Check sslClientCert
                cert_path = ldap.get('sslClientCert')
                if cert_path in cert_paths:
                    usage_map[cert_path].append(CertificateUsage(
                        object_type='LDAP Server',
                        object_name=ldap['name'],
                        object_path=ldap['fullPath'],
                        field_name='sslClientCert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check LDAP servers in partition {partition}: {e}")
        
        # Check RADIUS servers
        try:
            print(f"    🔍 Checking RADIUS servers...")
            response = self._make_request('GET', f'/mgmt/tm/auth/radius-server?$filter=partition eq {partition}')
            for radius in response.json().get('items', []):
                server_config = radius.get('server', {})
                cert_path = server_config.get('sslCaCertFile')
                if cert_path in cert_paths:
                    usage_map[cert_path].append(CertificateUsage(
                        object_type='RADIUS Server',
                        object_name=radius['name'],
                        object_path=radius['fullPath'],
                        field_name='server.sslCaCertFile',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check RADIUS servers in partition {partition}: {e}")
        
        # Check Syslog destinations (usually global, but check per partition)
        try:
            print(f"    🔍 Checking Syslog destinations...")
            response = self._make_request('GET', f'/mgmt/tm/sys/syslog?$filter=partition eq {partition}')
            for syslog in response.json().get('items', []):
                remote_syslog = syslog.get('remotesyslog', {})
                cert_path = remote_syslog.get('cert')
                if cert_path in cert_paths:
                    usage_map[cert_path].append(CertificateUsage(
                        object_type='Syslog Destination',
                        object_name=syslog.get('name', 'syslog'),
                        object_path=syslog.get('fullPath', f'/{partition}/syslog'),
                        field_name='remotesyslog.cert',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check Syslog destinations in partition {partition}: {e}")

def process_multiple_devices(devices: List[DeviceInfo], username: str = "", password: str = "", 
                           expiry_days: int = 30, report_only: bool = False, 
                           tls_version: str = 'auto', ciphers: str = None,
                           use_bulk_optimization: bool = True) -> BatchCleanupReport:
    """
    Process certificate cleanup for multiple F5 devices
    
    Args:
        devices: List of DeviceInfo objects
        username: Default username if not specified in CSV
        password: Default password if not specified in CSV  
        expiry_days: Days ahead to consider certificates as expiring
        report_only: Whether to only generate reports without cleanup
        tls_version: TLS version strategy for all devices
        ciphers: Custom cipher suite for all devices
        use_bulk_optimization: Whether to use bulk optimization for certificate checking
        
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
                protected_expired=[],
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
                test_connection=False,
                tls_version=tls_version,
                ciphers=ciphers,
                use_bulk_optimization=use_bulk_optimization
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
                    protected_expired=[],
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
                protected_expired=[],
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

def generate_batch_html_report(batch_report: BatchCleanupReport, output_file: str = None):
    """
    Generate HTML report for batch certificate cleanup across multiple devices
    
    Args:
        batch_report: BatchCleanupReport object
        output_file: Output HTML file path (auto-generated if None)
    """
    # Auto-generate filename with timestamp if not provided
    if output_file is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"f5_batch_cert_cleanup_report_{timestamp}.html"
    
    print(f"📄 Generating batch HTML report: {output_file}")
    
    # Calculate totals across all devices
    total_certs = sum(r.total_certificates for r in batch_report.reports if r.connection_successful)
    total_expired = sum(len(r.expired_certificates) for r in batch_report.reports if r.connection_successful)
    total_expiring = sum(len(r.expiring_certificates) for r in batch_report.reports if r.connection_successful)
    total_unused_expired = sum(len(r.unused_expired) for r in batch_report.reports if r.connection_successful)
    total_used_expired = sum(len(r.used_expired) for r in batch_report.reports if r.connection_successful)
    total_protected = sum(len(getattr(r, 'protected_expired', [])) for r in batch_report.reports if r.connection_successful)
    
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
                <div class="stat-card">
                    <div class="stat-number">{total_protected}</div>
                    <div>Protected (Default)</div>
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
                <h3>❌ {report.device_hostname} ({report.device_ip.replace('https://', '').replace('http://', '')})</h3>
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
                <h3>🖥️ {report.device_hostname} ({report.device_ip.replace('https://', '').replace('http://', '')})</h3>
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
                    <div class="stat-number">{len(report.unused_expired)}</div>
                    <div>Safe to Delete</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(getattr(report, 'protected_expired', []))}</div>
                    <div>Protected</div>
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
                         <th>Corresponding Key</th>
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
                    key_info = cert.corresponding_key if cert.corresponding_key else "❌ No key"
                    
                    html_content += f"""
                    <tr>
                        <td>{cert.name}</td>
                        <td>{key_info}</td>
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
  # Single device (auto-generates report_192_168_1_100.html and backup_192_168_1_100.json)
  python f5_cert_cleanup.py --host 192.168.1.100 --username admin
  python f5_cert_cleanup.py --host mybigip.local --expiry-days 45 --report-only
  
  # Multiple devices from CSV (auto-generates batch_report_YYYYMMDD_HHMMSS.html)
  python f5_cert_cleanup.py --devices-csv devices.csv --username admin
  python f5_cert_cleanup.py --devices-csv devices.csv --username admin --report-only
  
  # Custom filenames
  python f5_cert_cleanup.py --host 192.168.1.100 --username admin --report-file custom_report.html
  python f5_cert_cleanup.py --devices-csv devices.csv --username admin --batch-report-file custom_batch.html
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
                       help='HTML report filename (default: auto-generated with device IP)')
    parser.add_argument('--batch-report-file', default='f5_batch_cert_cleanup_report.html',
                       help='Batch HTML report filename for CSV mode (default: auto-generated with timestamp)')
    
    # TLS Configuration
    parser.add_argument('--tls-version', default='auto',
                       choices=['auto', 'legacy', 'tlsv1', 'tlsv1_1', 'tlsv1_2', 'tlsv1_3'],
                       help='TLS version strategy (default: auto)')
    parser.add_argument('--ciphers',
                       help='Custom cipher suite string for TLS connections')
    
    # Performance Configuration
    parser.add_argument('--disable-bulk-optimization', action='store_true',
                       help='Disable bulk optimization for certificate usage checking (slower but more compatible)')
    
    args = parser.parse_args()
    
    # Convert disable flag to use flag
    use_bulk_optimization = not args.disable_bulk_optimization
    
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
                args.report_only,
                args.tls_version,
                args.ciphers,
                use_bulk_optimization
            )
            
            # Generate batch HTML report
            # Use provided filename or auto-generate with timestamp
            batch_report_file = args.batch_report_file if args.batch_report_file != 'f5_batch_cert_cleanup_report.html' else None
            generate_batch_html_report(batch_report, batch_report_file)
            
            # Print final summary
            print(f"\n🎉 Batch processing completed!")
            print(f"  📋 Total devices processed: {batch_report.total_devices}")
            print(f"  ✅ Successful connections: {batch_report.successful_devices}")
            print(f"  ❌ Failed connections: {batch_report.failed_devices}")
            
            total_expired = sum(len(r.expired_certificates) for r in batch_report.reports if r.connection_successful)
            total_safe_delete = sum(len(r.unused_expired) for r in batch_report.reports if r.connection_successful)
            total_keys_mapped = sum(len([cert for cert in r.expired_certificates if cert.corresponding_key]) for r in batch_report.reports if r.connection_successful)
            
            print(f"  🔒 Total expired certificates found: {total_expired}")
            print(f"  🔑 Total SSL keys mapped: {total_keys_mapped}")
            print(f"  🗑️  Total safe to delete: {total_safe_delete}")
            
        else:
            # Single device mode
            print("🖥️  Single device mode")
            
            # Get password if not provided
            if not args.password:
                args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
            
            # Initialize F5 connection
            f5_cleanup = F5CertificateCleanup(
                args.host, 
                args.username, 
                args.password, 
                args.expiry_days,
                tls_version=args.tls_version,
                ciphers=args.ciphers,
                use_bulk_optimization=use_bulk_optimization
            )
            
            # Discover certificates
            certificates = f5_cleanup.discover_certificates()
            
            if not certificates:
                print("ℹ️  No certificates found on the F5 device")
                return
            
            # Analyze certificates
            report = f5_cleanup.analyze_certificates(certificates)
            
            # Generate HTML report (single device format)
            # Use provided filename or auto-generate with device IP
            report_file = args.report_file if args.report_file != 'f5_cert_cleanup_report.html' else None
            f5_cleanup.generate_html_report(report, report_file)
            
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
            print(f"  🔑 Deleted SSL keys: {stats['deleted_keys']}")
            print(f"  🔄 Dereferenced objects: {stats['dereferenced']}")
            
            if stats['failed_dereference'] or stats['failed_delete'] or stats['failed_key_delete']:
                print(f"  ❌ Failed dereferencing: {stats['failed_dereference']}")
                print(f"  ❌ Failed certificate deletions: {stats['failed_delete']}")
                print(f"  ❌ Failed key deletions: {stats['failed_key_delete']}")
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 