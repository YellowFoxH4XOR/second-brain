#!/usr/bin/env python3
"""
F5 BIG-IP Certificate Cleanup Script

This script automates the process of identifying, analyzing, and safely removing
expired SSL certificates from F5 BIG-IP devices using the iControl REST API.

Key Features:
- Multi-partition certificate discovery and cleanup
- Comprehensive service impact analysis (Virtual Servers & GTM)
- Bulk optimization for large-scale operations
- Certificate type-based protection (bundles, defaults)
- Detailed HTML reporting with failure tracking
- Configuration diff reports with before/after comparison
- Safe dereferencing with service status validation

Author: Generated for Certificate Cleanup Automation
Version: 2.1 (Simplified - Standard TLS)
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
import difflib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_standard_session(max_retries=3):
    """
    Create a standard requests session for F5 BIG-IP devices
    
    Args:
        max_retries: Number of retry attempts
        
    Returns:
        Configured requests session
    """
    session = requests.Session()
    
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
    certificate_type: str = ""  # Certificate type (e.g., "Certificate Bundle", "Certificate")

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
                 test_connection: bool = True, use_bulk_optimization: bool = True):
        """
        Initialize F5 connection and configuration
        
        Args:
            host: F5 BIG-IP hostname or IP
            username: F5 username
            password: F5 password
            expiry_days: Days ahead to consider certificates as "expiring soon"
            test_connection: Whether to test connection during initialization
            use_bulk_optimization: Whether to use bulk optimization for certificate usage checking
        """
        self.original_host = host
        self.host = host.rstrip('/')
        if not self.host.startswith('https://'):
            self.host = f"https://{self.host}"
        
        self.auth = (username, password)
        self.expiry_days = expiry_days
        self.use_bulk_optimization = use_bulk_optimization
        
        # Create session
        self.session = self._create_f5_session()
        
        # Cache for module availability checks
        self._gtm_available = None
        self._apm_available = None
        
        # Test connection if requested
        if test_connection:
            try:
                self._test_connection()
            except Exception as e:
                print(f"❌ Failed to connect to F5 device: {e}")
                sys.exit(1)
    
    def _create_f5_session(self):
        """Create a session for F5 API communication"""
        session = create_standard_session(max_retries=3)
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
                            partition=cert_partition,
                            certificate_type=cert_data.get('certificateType', '')
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
                            partition=cert_partition,
                            certificate_type=cert_data.get('certificateType', '')
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
                
                # NEW: Check for trusted signing certificates in Client-SSL profiles
                # Check caFile field for trusted CA certificates
                if profile.get('caFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Client-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='caFile (Trusted CA)',
                        partition=partition
                    ))
                
                # Check chainFile field for certificate chain
                if profile.get('chainFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Client-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='chainFile (Certificate Chain)',
                        partition=partition
                    ))
                
                # Check trustedCertAuthorities field
                trusted_ca = profile.get('trustedCertAuthorities', [])
                if isinstance(trusted_ca, list):
                    for ca in trusted_ca:
                        if ca == cert_path:
                            usage_list.append(CertificateUsage(
                                object_type='Client-SSL Profile',
                                object_name=profile['name'],
                                object_path=profile['fullPath'],
                                field_name='trustedCertAuthorities (Trusted CA)',
                                partition=partition
                            ))
                elif trusted_ca == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Client-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='trustedCertAuthorities (Trusted CA)',
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
                
                # NEW: Check for trusted signing certificates in Server-SSL profiles
                # Check caFile field for trusted CA certificates
                if profile.get('caFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Server-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='caFile (Trusted CA)',
                        partition=partition
                    ))
                
                # Check chainFile field for certificate chain
                if profile.get('chainFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Server-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='chainFile (Certificate Chain)',
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
        
        # NEW: Check Certificate Validator Trust Stores
        try:
            response = self._make_request('GET', f'/mgmt/tm/sys/crypto/cert-validator/truststore?$filter=partition eq {partition}')
            for truststore in response.json().get('items', []):
                trusted_certs = truststore.get('trustedCerts', [])
                if isinstance(trusted_certs, list):
                    for trusted_cert in trusted_certs:
                        if trusted_cert == cert_path:
                            usage_list.append(CertificateUsage(
                                object_type='Certificate Trust Store',
                                object_name=truststore['name'],
                                object_path=truststore['fullPath'],
                                field_name='trustedCerts (Trust Store)',
                                partition=partition
                            ))
                elif trusted_certs == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Certificate Trust Store',
                        object_name=truststore['name'],
                        object_path=truststore['fullPath'],
                        field_name='trustedCerts (Trust Store)',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Certificate Trust Stores in partition {partition}: {e}")
        
        # NEW: Check HTTP profiles for trusted certificates
        try:
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/http?$filter=partition eq {partition}')
            for http_profile in response.json().get('items', []):
                # Check for SSL client certificates in HTTP profiles
                if http_profile.get('trustedCertAuthorities') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='HTTP Profile',
                        object_name=http_profile['name'],
                        object_path=http_profile['fullPath'],
                        field_name='trustedCertAuthorities (HTTP Profile)',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check HTTP profiles in partition {partition}: {e}")
            
        # NEW: Check WebAcceleration profiles
        try:
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/web-acceleration?$filter=partition eq {partition}')
            for wa_profile in response.json().get('items', []):
                if wa_profile.get('sslCaCertFile') == cert_path:
                    usage_list.append(CertificateUsage(
                        object_type='Web Acceleration Profile',
                        object_name=wa_profile['name'],
                        object_path=wa_profile['fullPath'],
                        field_name='sslCaCertFile (Web Acceleration)',
                        partition=partition
                    ))
        except Exception as e:
            print(f"⚠️  Warning: Could not check Web Acceleration profiles in partition {partition}: {e}")
    
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
        blocked_by_active_services = []
        
        # Filter out default certificates first (they are protected)
        non_protected_expired = []
        for cert in expired_certs:
            if self.is_default_certificate(cert.name, cert.full_path, cert.certificate_type):
                protected_expired.append(cert)
                print(f"  🛡️  Default certificate protected from deletion: {cert.name} (partition: {cert.partition}, type: {cert.certificate_type})")
            else:
                non_protected_expired.append(cert)
        
        # Only check usage for non-protected expired certificates
        if non_protected_expired:
            if self.use_bulk_optimization:
                print(f"🚀 Using bulk optimization for {len(non_protected_expired)} non-protected expired certificates...")
                usage_map = self.check_certificate_usage_bulk(non_protected_expired, partitions)
            else:
                print(f"📋 Using individual certificate checking for {len(non_protected_expired)} certificates...")
                usage_map = {}
                for cert in non_protected_expired:
                    print(f"  📋 Checking usage for: {cert.name} (partition: {cert.partition})")
                    usage = self.check_certificate_usage(cert.full_path, partitions)
                    usage_map[cert.full_path] = usage
            
            # 🚨 NEW: Comprehensive service impact analysis
            print(f"\n🚨 Performing comprehensive service impact analysis...")
            service_impact_analysis = self.analyze_service_impact(non_protected_expired, usage_map, partitions)
            
            # Process results with service impact consideration
            for cert in non_protected_expired:
                usage = usage_map.get(cert.full_path, [])
                impact = service_impact_analysis.get(cert.full_path, {})
                
                if not usage:
                    unused_expired.append(cert)
                    print(f"  ✅ {cert.name} - Not in use (safe to delete)")
                else:
                    # Check if blocked by active services
                    active_services = impact.get('active_services', [])
                    if active_services:
                        blocked_by_active_services.append((cert, usage, active_services))
                        print(f"  🚫 {cert.name} - BLOCKED by {len(active_services)} active service(s)")
                        for service in active_services:
                            print(f"    ⚠️  Active {service['type']}: {service['name']} (status: {service['status']})")
                    else:
                        used_expired.append((cert, usage))
                        print(f"  ⚠️  {cert.name} - In use by {len(usage)} object(s) (all services inactive)")
        else:
            print("ℹ️  No non-protected expired certificates to check")
        
        # Create extended cleanup report
        report = CleanupReport(
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
        
        # Add service impact data as additional attribute
        report.blocked_by_active_services = blocked_by_active_services
        
        return report
    
    def analyze_service_impact(self, certificates: List[CertificateInfo], usage_map: Dict[str, List[CertificateUsage]], 
                             partitions: List[str]) -> Dict[str, Dict[str, any]]:
        """
        Comprehensive analysis of service impact for certificate cleanup
        
        This method implements the corrected logic:
        1. Find all Virtual Servers and their corresponding profiles
        2. Find all expired certificates and profiles they use
        3. Match these to identify affected Virtual Servers or Wide IPs
        4. Check service status - only allow deletion if services are down
        
        Args:
            certificates: List of expired certificates to analyze
            usage_map: Map of certificate paths to their usage locations
            partitions: List of partitions to check
            
        Returns:
            Dictionary mapping certificate paths to service impact analysis
        """
        print("  🔍 Step 1: Discovering all Virtual Servers and their SSL profiles...")
        
        # Step 1: Build comprehensive map of Virtual Servers and their SSL profiles
        virtual_server_profiles = self._discover_virtual_server_ssl_profiles(partitions)
        
        print(f"    📊 Found {len(virtual_server_profiles)} Virtual Server(s) with SSL profiles")
        
        # Step 2: Build comprehensive map of GTM objects if available
        gtm_object_monitors = {}
        if self.is_gtm_available():
            print("  🌐 Step 2: Discovering GTM objects and their monitors...")
            gtm_object_monitors = self._discover_gtm_object_monitors(partitions)
            print(f"    📊 Found {len(gtm_object_monitors)} GTM object(s) with HTTPS monitors")
        
        # Step 3: Analyze impact for each certificate
        print("  🔗 Step 3: Matching expired certificates to affected services...")
        
        service_impact = {}
        
        for cert in certificates:
            cert_path = cert.full_path
            usage_list = usage_map.get(cert_path, [])
            
            impact_analysis = {
                'certificate': cert,
                'usage_count': len(usage_list),
                'affected_profiles': [],
                'affected_virtual_servers': [],
                'affected_gtm_objects': [],
                'active_services': [],
                'inactive_services': [],
                'blocking_analysis': 'safe'  # 'safe', 'blocked', 'no_usage'
            }
            
            if not usage_list:
                impact_analysis['blocking_analysis'] = 'no_usage'
                service_impact[cert_path] = impact_analysis
                continue
            
            # Analyze each usage location
            for usage in usage_list:
                profile_info = {
                    'type': usage.object_type,
                    'name': usage.object_name,
                    'partition': usage.partition,
                    'field': usage.field_name
                }
                impact_analysis['affected_profiles'].append(profile_info)
                
                # Check if this profile is used by any Virtual Servers
                if usage.object_type in ['Client-SSL Profile', 'Server-SSL Profile']:
                    affected_vs = self._find_virtual_servers_using_profile(
                        usage.object_name, usage.object_type, usage.partition, virtual_server_profiles
                    )
                    
                    for vs_info in affected_vs:
                        vs_status = self._get_comprehensive_virtual_server_status(vs_info['name'], vs_info['partition'])
                        
                        service_info = {
                            'type': 'Virtual Server',
                            'name': vs_info['name'],
                            'partition': vs_info['partition'],
                            'status': vs_status['status_text'],
                            'enabled': vs_status['enabled'],
                            'available': vs_status['available'],
                            'safe_for_cert_cleanup': vs_status['safe_for_cert_cleanup']
                        }
                        
                        impact_analysis['affected_virtual_servers'].append(service_info)
                        
                        if vs_status['safe_for_cert_cleanup']:
                            impact_analysis['inactive_services'].append(service_info)
                        else:
                            impact_analysis['active_services'].append(service_info)
                
                # Check if this monitor is used by any GTM objects
                elif usage.object_type == 'GTM HTTPS Monitor' and self.is_gtm_available():
                    affected_gtm = self._find_gtm_objects_using_monitor_comprehensive(
                        usage.object_name, usage.partition, gtm_object_monitors
                    )
                    
                    for gtm_info in affected_gtm:
                        gtm_status = self._get_comprehensive_gtm_object_status(gtm_info['name'], gtm_info['type'], gtm_info['partition'])
                        
                        service_info = {
                            'type': f"GTM {gtm_info['type']}",
                            'name': gtm_info['name'],
                            'partition': gtm_info['partition'],
                            'status': gtm_status['status_text'],
                            'enabled': gtm_status['enabled'],
                            'available': gtm_status['available'],
                            'safe_for_cert_cleanup': gtm_status['safe_for_cert_cleanup']
                        }
                        
                        impact_analysis['affected_gtm_objects'].append(service_info)
                        
                        if gtm_status['safe_for_cert_cleanup']:
                            impact_analysis['inactive_services'].append(service_info)
                        else:
                            impact_analysis['active_services'].append(service_info)
            
            # Determine overall blocking status
            if impact_analysis['active_services']:
                impact_analysis['blocking_analysis'] = 'blocked'
            else:
                impact_analysis['blocking_analysis'] = 'safe'
            
            service_impact[cert_path] = impact_analysis
            
            # Log analysis results
            if impact_analysis['active_services']:
                print(f"    🚫 {cert.name}: BLOCKED by {len(impact_analysis['active_services'])} active service(s)")
            elif impact_analysis['affected_virtual_servers'] or impact_analysis['affected_gtm_objects']:
                total_services = len(impact_analysis['affected_virtual_servers']) + len(impact_analysis['affected_gtm_objects'])
                print(f"    ✅ {cert.name}: Safe - {total_services} service(s) are inactive")
            else:
                print(f"    ℹ️  {cert.name}: No Virtual Server/GTM impact")
        
        return service_impact
    
    def _discover_virtual_server_ssl_profiles(self, partitions: List[str]) -> Dict[str, Dict[str, any]]:
        """
        Discover all Virtual Servers and their SSL profile associations
        
        Returns:
            Dictionary mapping VS full path to VS info with SSL profiles
        """
        virtual_servers = {}
        
        for partition in partitions:
            try:
                response = self._make_request('GET', f'/mgmt/tm/ltm/virtual?$filter=partition eq {partition}')
                
                for vs in response.json().get('items', []):
                    vs_name = vs.get('name')
                    vs_full_path = vs.get('fullPath')
                    profiles = vs.get('profiles', {})
                    
                    ssl_profiles = {
                        'client_ssl': [],
                        'server_ssl': []
                    }
                    
                    # Extract SSL profiles
                    for profile_path, profile_config in profiles.items():
                        context = profile_config.get('context', '')
                        if context == 'clientside':
                            ssl_profiles['client_ssl'].append({
                                'name': profile_path.split('/')[-1],
                                'full_path': profile_path,
                                'partition': profile_path.split('/')[1] if profile_path.startswith('/') else partition
                            })
                        elif context == 'serverside':
                            ssl_profiles['server_ssl'].append({
                                'name': profile_path.split('/')[-1],
                                'full_path': profile_path,
                                'partition': profile_path.split('/')[1] if profile_path.startswith('/') else partition
                            })
                    
                    # Only store VS if it has SSL profiles
                    if ssl_profiles['client_ssl'] or ssl_profiles['server_ssl']:
                        virtual_servers[vs_full_path] = {
                            'name': vs_name,
                            'partition': partition,
                            'full_path': vs_full_path,
                            'ssl_profiles': ssl_profiles
                        }
                        
            except Exception as e:
                print(f"    ⚠️  Warning: Could not discover Virtual Servers in partition {partition}: {e}")
        
        return virtual_servers
    
    def _discover_gtm_object_monitors(self, partitions: List[str]) -> Dict[str, Dict[str, any]]:
        """
        Discover all GTM objects and their HTTPS monitor associations
        
        Returns:
            Dictionary mapping GTM object path to object info with monitors
        """
        gtm_objects = {}
        
        if not self.is_gtm_available():
            return gtm_objects
        
        gtm_types = ['pool', 'wideip']
        record_types = ['a', 'aaaa', 'cname', 'mx', 'naptr', 'srv']
        
        for partition in partitions:
            for gtm_type in gtm_types:
                for record_type in record_types:
                    try:
                        response = self._make_request('GET', f'/mgmt/tm/gtm/{gtm_type}/{record_type}?$filter=partition eq {partition}')
                        
                        for obj in response.json().get('items', []):
                            obj_name = obj.get('name')
                            obj_full_path = obj.get('fullPath')
                            
                            # Extract HTTPS monitors
                            https_monitors = []
                            monitor_config = obj.get('monitor', '')
                            
                            if 'https' in monitor_config.lower():
                                # Parse monitor configuration
                                monitor_parts = monitor_config.split()
                                for part in monitor_parts:
                                    if 'https' in part.lower() and part.startswith('/'):
                                        https_monitors.append({
                                            'name': part.split('/')[-1],
                                            'full_path': part,
                                            'partition': part.split('/')[1] if part.startswith('/') else partition
                                        })
                            
                            # Only store if it has HTTPS monitors
                            if https_monitors:
                                gtm_objects[obj_full_path] = {
                                    'name': obj_name,
                                    'type': f"{record_type.upper()} {gtm_type.title()}",
                                    'partition': partition,
                                    'full_path': obj_full_path,
                                    'https_monitors': https_monitors
                                }
                                
                    except Exception as e:
                        # Expected for non-existent record types
                        continue
        
        return gtm_objects
    
    def _find_virtual_servers_using_profile(self, profile_name: str, profile_type: str, profile_partition: str, 
                                          virtual_server_profiles: Dict[str, Dict[str, any]]) -> List[Dict[str, str]]:
        """
        Find Virtual Servers that use a specific SSL profile from pre-discovered data
        
        Returns:
            List of Virtual Server info dictionaries
        """
        affected_vs = []
        profile_full_path = f"/{profile_partition}/{profile_name}"
        
        for vs_path, vs_info in virtual_server_profiles.items():
            ssl_profiles = vs_info['ssl_profiles']
            
            # Check both client-ssl and server-ssl profiles
            profile_list = []
            if profile_type == 'Client-SSL Profile':
                profile_list = ssl_profiles['client_ssl']
            elif profile_type == 'Server-SSL Profile':
                profile_list = ssl_profiles['server_ssl']
            
            for profile in profile_list:
                if (profile['full_path'] == profile_full_path or 
                    profile['name'] == profile_name):
                    affected_vs.append({
                        'name': vs_info['name'],
                        'partition': vs_info['partition'],
                        'full_path': vs_info['full_path']
                    })
                    break
        
        return affected_vs
    
    def _find_gtm_objects_using_monitor_comprehensive(self, monitor_name: str, monitor_partition: str, 
                                                    gtm_object_monitors: Dict[str, Dict[str, any]]) -> List[Dict[str, str]]:
        """
        Find GTM objects that use a specific HTTPS monitor from pre-discovered data
        
        Returns:
            List of GTM object info dictionaries
        """
        affected_gtm = []
        monitor_full_path = f"/{monitor_partition}/{monitor_name}"
        
        for gtm_path, gtm_info in gtm_object_monitors.items():
            for monitor in gtm_info['https_monitors']:
                if (monitor['full_path'] == monitor_full_path or 
                    monitor['name'] == monitor_name):
                    affected_gtm.append({
                        'name': gtm_info['name'],
                        'type': gtm_info['type'],
                        'partition': gtm_info['partition'],
                        'full_path': gtm_info['full_path']
                    })
                    break
        
        return affected_gtm
    
    def _get_comprehensive_virtual_server_status(self, vs_name: str, vs_partition: str) -> Dict[str, any]:
        """
        Get comprehensive Virtual Server status for certificate cleanup safety
        
        Returns:
            Dictionary with detailed status including safety assessment
        """
        try:
            vs_path = f"~{vs_partition}~{vs_name}".replace('/', '~')
            response = self._make_request('GET', f'/mgmt/tm/ltm/virtual/{vs_path}')
            vs_config = response.json()
            
            # Check enabled/disabled state
            enabled = vs_config.get('enabled', True)
            disabled = vs_config.get('disabled', False)
            is_enabled = enabled and not disabled
            
            # Get availability state from stats
            availability_state = 'unknown'
            is_available = True  # Conservative default
            
            try:
                stats_response = self._make_request('GET', f'/mgmt/tm/ltm/virtual/{vs_path}/stats')
                stats = stats_response.json()
                
                entries = stats.get('entries', {})
                for entry_key, entry_data in entries.items():
                    nested_stats = entry_data.get('nestedStats', {}).get('entries', {})
                    if 'status.availabilityState' in nested_stats:
                        availability_state = nested_stats['status.availabilityState']['description']
                        break
                
                # Only 'offline' and 'down' states are safe for certificate cleanup
                safe_availability_states = ['offline', 'down', 'disabled']
                is_available = availability_state.lower() not in safe_availability_states
                
            except Exception:
                # If we can't get stats, assume available (conservative)
                pass
            
            # Certificate cleanup is safe ONLY if VS is disabled AND offline/down
            safe_for_cert_cleanup = not is_enabled and not is_available
            
            # Generate descriptive status text
            if not is_enabled and not is_available:
                status_text = f"Disabled & {availability_state}"
            elif not is_enabled:
                status_text = f"Disabled (availability: {availability_state})"
            elif not is_available:
                status_text = f"Enabled but {availability_state}"
            else:
                status_text = f"Active (enabled & {availability_state})"
            
            return {
                'enabled': is_enabled,
                'available': is_available,
                'availability_state': availability_state,
                'safe_for_cert_cleanup': safe_for_cert_cleanup,
                'status_text': status_text
            }
            
        except Exception as e:
            # If we can't determine status, assume unsafe (conservative)
            return {
                'enabled': True,
                'available': True,
                'availability_state': 'unknown',
                'safe_for_cert_cleanup': False,
                'status_text': f"Status check failed: {e}"
            }
    
    def _get_comprehensive_gtm_object_status(self, obj_name: str, obj_type: str, obj_partition: str) -> Dict[str, any]:
        """
        Get comprehensive GTM object status for certificate cleanup safety
        
        Returns:
            Dictionary with detailed status including safety assessment
        """
        try:
            # Parse object type to get GTM type and record type
            type_parts = obj_type.lower().split()
            if len(type_parts) >= 2:
                record_type = type_parts[0]  # e.g., 'a', 'aaaa'
                gtm_type = type_parts[1]     # e.g., 'pool', 'wideip'
            else:
                return {
                    'enabled': True,
                    'available': True,
                    'safe_for_cert_cleanup': False,
                    'status_text': "Unknown GTM object type"
                }
            
            obj_path = f"~{obj_partition}~{obj_name}".replace('/', '~')
            response = self._make_request('GET', f'/mgmt/tm/gtm/{gtm_type}/{record_type}/{obj_path}')
            obj_config = response.json()
            
            # Check enabled/disabled state
            enabled = obj_config.get('enabled', True)
            disabled = obj_config.get('disabled', False)
            is_enabled = enabled and not disabled
            
            # For GTM objects, if enabled assume available (GTM stats are complex)
            # Certificate cleanup is safe ONLY if GTM object is disabled
            safe_for_cert_cleanup = not is_enabled
            
            # Generate descriptive status text
            status_text = "Enabled" if is_enabled else "Disabled"
            
            return {
                'enabled': is_enabled,
                'available': is_enabled,  # Simplified for GTM
                'safe_for_cert_cleanup': safe_for_cert_cleanup,
                'status_text': status_text
            }
            
        except Exception as e:
            # If we can't determine status, assume unsafe (conservative)
            return {
                'enabled': True,
                'available': True,
                'safe_for_cert_cleanup': False,
                'status_text': f"Status check failed: {e}"
            }
    
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
        
        # Get blocked services information if available
        blocked_by_services = getattr(report, 'blocked_by_active_services', [])
        
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
        .blocked {{ background-color: #ffeaa7 !important; }}
        .usage-details {{ background: #f8f9fa; padding: 10px; border-left: 4px solid #007acc; margin: 5px 0; }}
        .service-details {{ background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 5px 0; }}
        .badge {{ padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; color: black; }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-blocked {{ background: #e17055; color: white; }}
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
                <li><strong>Blocked by Active Services:</strong> {len(blocked_by_services)}</li>
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
                            <th>Type</th>
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
            cert_type_display = cert.certificate_type if cert.certificate_type else "Unknown"
            html_content += f"""
                <tr class="safe-delete">
                    <td>{cert.name}</td>
                    <td>{cert.partition}</td>
                    <td>{cert_type_display}</td>
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
        
        <h2>🚫 Certificates Blocked by Active Services</h2>
        <p>These expired certificates cannot be deleted because they are used by active Virtual Servers or GTM objects:</p>
"""
        
        if blocked_by_services:
            for cert, usage_list, active_services in blocked_by_services:
                key_info = cert.corresponding_key if cert.corresponding_key else "❌ No key found"
                html_content += f"""
        <div class="service-details">
            <h4>🚫 {cert.name} (Partition: {cert.partition})</h4>
            <p><strong>Expiration:</strong> {cert.expiration_date.strftime('%Y-%m-%d %H:%M:%S')} 
               ({abs(cert.days_until_expiry)} days expired)</p>
            <p><strong>Subject:</strong> {cert.subject}</p>
            <p><strong>Corresponding Key:</strong> {key_info}</p>
            <p><strong>BLOCKED by {len(active_services)} active service(s):</strong></p>
            <ul>
"""
                for service in active_services:
                    html_content += f"""
                <li><strong>{service['type']}:</strong> {service['name']} (partition: {service['partition']}) - Status: {service['status']}</li>
"""
                html_content += """
            </ul>
            <p><strong>💡 Resolution:</strong> Disable the above services during a maintenance window to allow certificate cleanup.</p>
        </div>
"""
        else:
            html_content += """
        <div style="background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; border: 1px solid #c3e6cb;">
            <p>✅ No certificates are blocked by active services.</p>
        </div>
"""
        
        html_content += """
        
        <h2>🛡️ Protected Certificates (Default)</h2>
        <p>These expired default certificates are protected from deletion and shown for informational purposes only:</p>
        <table class="cert-table">
            <thead>
                                        <tr>
                            <th>Certificate Name</th>
                            <th>Partition</th>
                            <th>Type</th>
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
            cert_type_display = cert.certificate_type if cert.certificate_type else "Unknown"
            html_content += f"""
                                  <tr style="background-color: #e1f5fe !important;">
                      <td>{cert.name}</td>
                      <td>{cert.partition}</td>
                      <td>{cert_type_display}</td>
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
        return output_file
    
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
        try:
            print(f"    🔍 Looking for default certificate in partition: {partition}")
            
            # Try to find partition-specific default certificate first
            partition_default_cert = f"/{partition}/default.crt"
            partition_default_key = f"/{partition}/default.key"
            
            # Check if partition-specific defaults exist
            try:
                response = self._make_request('GET', f'/mgmt/tm/sys/file/ssl-cert?$filter=partition eq {partition}')
                certificates = response.json().get('items', [])
                
                for cert in certificates:
                    cert_name = cert.get('name', '')
                    if cert_name == 'default.crt':
                        print(f"    ✅ Found partition-specific default certificate: {partition_default_cert}")
                        return partition_default_cert, partition_default_key
                
                print(f"    ℹ️  No partition-specific default found in {partition}, using Common default")
                
            except Exception as e:
                print(f"    ⚠️  Could not check for partition-specific defaults in {partition}: {e}")
            
            # Fall back to Common default
            common_default_cert = "/Common/default.crt"
            common_default_key = "/Common/default.key"
            
            # Verify Common default exists
            try:
                response = self._make_request('GET', '/mgmt/tm/sys/file/ssl-cert?$filter=partition eq Common')
                certificates = response.json().get('items', [])
                
                for cert in certificates:
                    if cert.get('name') == 'default.crt':
                        print(f"    ✅ Using Common default certificate: {common_default_cert}")
                        return common_default_cert, common_default_key
                
                print(f"    ⚠️  Warning: No default.crt found in Common partition!")
                
            except Exception as e:
                print(f"    ⚠️  Warning: Could not verify Common default certificate: {e}")
            
            # Return Common default even if verification failed
            print(f"    🔄 Defaulting to: {common_default_cert} (may not exist)")
            return common_default_cert, common_default_key
            
        except Exception as e:
            print(f"    ❌ Error in get_default_certificate_for_partition: {e}")
            # Fall back to Common default as last resort
            return "/Common/default.crt", "/Common/default.key"
    

    def dereference_certificate(self, cert_path: str, usage: CertificateUsage) -> bool:
        """
        Dereference a certificate from an F5 object and replace with appropriate default for the partition
        
        NOTE: Service impact checking is now done upfront in analyze_service_impact() method.
        This method only performs the actual dereferencing operation.
        
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
            
            # Construct proper F5 REST API path with partition handling
            # F5 REST API requires: /endpoint/~Partition~ObjectName format for non-Common objects
            if usage.partition and usage.partition != 'Common':
                object_path = f"~{usage.partition}~{usage.object_name}"
            else:
                object_path = f"~Common~{usage.object_name}"
            
            # URL encode the object path
            encoded_object_path = object_path.replace('/', '~')
            
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
                endpoint = f"/mgmt/tm/ltm/profile/client-ssl/{encoded_object_path}"
                
            elif usage.object_type == 'Server-SSL Profile':
                # Replace in Server-SSL profile
                update_data = {
                    "cert": default_cert,
                    "key": default_key
                }
                endpoint = f"/mgmt/tm/ltm/profile/server-ssl/{encoded_object_path}"
                
            elif usage.object_type in ['LTM HTTPS Monitor', 'GTM HTTPS Monitor']:
                # Replace in monitor
                update_data = {
                    "cert": default_cert
                }
                if 'LTM' in usage.object_type:
                    endpoint = f"/mgmt/tm/ltm/monitor/https/{encoded_object_path}"
                else:
                    endpoint = f"/mgmt/tm/gtm/monitor/https/{encoded_object_path}"
            
            elif usage.object_type == 'OCSP Responder':
                # Replace in OCSP responder
                update_data = {
                    "trustedResponders": [default_cert]
                }
                endpoint = f"/mgmt/tm/sys/crypto/cert-validator/ocsp/{encoded_object_path}"
            
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
                endpoint = f"/mgmt/tm/apm/profile/authentication/{encoded_object_path}"
            
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
                endpoint = f"/mgmt/tm/auth/ldap/{encoded_object_path}"
            
            elif usage.object_type == 'RADIUS Server':
                # Replace in RADIUS server
                update_data = {
                    "server": {
                        "sslCaCertFile": default_cert
                    }
                }
                endpoint = f"/mgmt/tm/auth/radius-server/{encoded_object_path}"
            
            elif usage.object_type == 'Syslog Destination':
                # Replace in Syslog destination
                update_data = {
                    "remotesyslog": {
                        "cert": default_cert
                    }
                }
                # Syslog is a system-wide setting, not partition-specific
                endpoint = f"/mgmt/tm/sys/syslog"
            
            else:
                print(f"    ❌ Unknown object type: {usage.object_type}")
                return False
            
            # Add debug information for troubleshooting
            print(f"    🔧 API Call: PATCH {endpoint}")
            print(f"    📝 Update data: {update_data}")
            
            response = self._make_request('PATCH', endpoint, json=update_data)
            
            if response.status_code in [200, 201, 202]:
                print(f"    ✅ Successfully dereferenced after safety checks")
                return True
            else:
                print(f"    ❌ API call failed with status {response.status_code}: {response.text}")
                return False
            
        except Exception as e:
            print(f"    ❌ Failed to dereference: {e}")
            print(f"    🔧 Debug info - Object: {usage.object_name}, Partition: {usage.partition}, Type: {usage.object_type}")
            print(f"    🔧 Debug info - Endpoint: {endpoint if 'endpoint' in locals() else 'Not constructed'}")
            print(f"    🔧 Debug info - Default cert: {default_cert if 'default_cert' in locals() else 'Not retrieved'}")
            return False
    
    def delete_ssl_key(self, key_name: str, partition: str = None) -> bool:
        """
        Delete an SSL key from F5
        
        Args:
            key_name: Name of SSL key to delete (can be simple name or full path)
            partition: Partition where the key resides (extracted if not provided)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Extract partition from key name if it's a full path
            if key_name.startswith('/') and '/' in key_name[1:]:
                # Full path format: /Partition/keyname.key
                path_parts = key_name.split('/')
                key_partition = path_parts[1]
                simple_key_name = path_parts[2]
            else:
                # Simple name format
                key_partition = partition or "Common"
                simple_key_name = key_name
            
            # Construct proper F5 REST API path with partition handling
            if key_partition and key_partition != 'Common':
                encoded_path = f"~{key_partition}~{simple_key_name}"
            else:
                encoded_path = f"~Common~{simple_key_name}"
            
            endpoint = f"/mgmt/tm/sys/file/ssl-key/{encoded_path}"
            
            print(f"  🔧 API Call: DELETE {endpoint}")
            response = self._make_request('DELETE', endpoint)
            
            if response.status_code in [200, 201, 202, 204]:
                print(f"  🔑 Deleted SSL key: {key_name}")
                return True
            else:
                print(f"  ❌ API call failed with status {response.status_code}: {response.text}")
                return False
            
        except Exception as e:
            print(f"  ❌ Failed to delete SSL key {key_name}: {e}")
            print(f"  🔧 Debug info - Key: {key_name}, Partition: {partition}")
            print(f"  🔧 Debug info - Endpoint: {endpoint if 'endpoint' in locals() else 'Not constructed'}")
            return False
    
    def delete_certificate(self, cert_name: str, key_name: str = "", partition: str = None) -> Tuple[bool, bool]:
        """
        Delete a certificate and its corresponding SSL key from F5
        
        Args:
            cert_name: Name of certificate to delete (can be simple name or full path)
            key_name: Name of corresponding SSL key to delete (optional)
            partition: Partition where the certificate resides (extracted if not provided)
            
        Returns:
            Tuple of (cert_deleted, key_deleted) success flags
        """
        cert_deleted = False
        key_deleted = False
        
        # Extract partition from certificate name if it's a full path
        if cert_name.startswith('/') and '/' in cert_name[1:]:
            # Full path format: /Partition/certname.crt
            path_parts = cert_name.split('/')
            cert_partition = path_parts[1]
            simple_cert_name = path_parts[2]
        else:
            # Simple name format
            cert_partition = partition or "Common"
            simple_cert_name = cert_name
        
        # Safety check: Never delete default certificates
        full_cert_path = f"/{cert_partition}/{simple_cert_name}"
        if self.is_default_certificate(simple_cert_name, full_cert_path):
            print(f"  🛡️  PROTECTED: Refusing to delete default certificate: {cert_name}")
            return False, False
        
        # Delete certificate
        try:
            # Construct proper F5 REST API path with partition handling
            if cert_partition and cert_partition != 'Common':
                encoded_path = f"~{cert_partition}~{simple_cert_name}"
            else:
                encoded_path = f"~Common~{simple_cert_name}"
            
            endpoint = f"/mgmt/tm/sys/file/ssl-cert/{encoded_path}"
            
            print(f"  🔧 API Call: DELETE {endpoint}")
            response = self._make_request('DELETE', endpoint)
            
            if response.status_code in [200, 201, 202, 204]:
                print(f"  ✅ Deleted certificate: {cert_name}")
                cert_deleted = True
            else:
                print(f"  ❌ API call failed with status {response.status_code}: {response.text}")
                cert_deleted = False
            
        except Exception as e:
            print(f"  ❌ Failed to delete certificate {cert_name}: {e}")
            print(f"  🔧 Debug info - Cert: {cert_name}, Partition: {cert_partition}")
            print(f"  🔧 Debug info - Endpoint: {endpoint if 'endpoint' in locals() else 'Not constructed'}")
        
        # Delete corresponding SSL key if provided
        if key_name:
            # Safety check for keys too
            if self.is_default_certificate(key_name, key_name):
                print(f"  🛡️  PROTECTED: Refusing to delete default key: {key_name}")
                key_deleted = True  # Consider successful to avoid error state
            else:
                try:
                    # Pass partition info to delete_ssl_key
                    key_deleted = self.delete_ssl_key(key_name, cert_partition)
                except Exception as e:
                    print(f"  ❌ Failed to delete SSL key {key_name}: {e}")
        else:
            key_deleted = True  # No key to delete, consider successful
        
        return cert_deleted, key_deleted
    
    def execute_cleanup(self, report: CleanupReport) -> Dict[str, any]:
        """
        Execute the certificate cleanup based on user confirmation
        
        Args:
            report: CleanupReport object
            
        Returns:
            Dictionary with cleanup statistics and detailed failure information
        """
        stats = {
            'deleted_unused': 0,
            'deleted_used': 0,
            'deleted_keys': 0,
            'dereferenced': 0,
            'failed_dereference': 0,
            'failed_delete': 0,
            'failed_key_delete': 0,
            'failed_certificates': [],  # Detailed list of failed certificate deletions
            'failed_keys': [],  # Detailed list of failed key deletions
            'failed_dereferences': [],  # Detailed list of failed dereferences
            'successful_deletions': [],  # List of successfully deleted certificates
            'successful_dereferences': []  # List of successful dereferences
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
                print(f"  📋 Deleting unused certificate: {cert.name} (partition: {cert.partition})")
                cert_deleted, key_deleted = self.delete_certificate(cert.name, cert.corresponding_key, cert.partition)
                if cert_deleted:
                    stats['deleted_unused'] += 1
                    stats['successful_deletions'].append({
                        'name': cert.name,
                        'full_path': cert.full_path,
                        'partition': cert.partition,
                        'type': 'unused_certificate',
                        'corresponding_key': cert.corresponding_key
                    })
                    if cert.corresponding_key and key_deleted:
                        stats['deleted_keys'] += 1
                    elif cert.corresponding_key and not key_deleted:
                        stats['failed_key_delete'] += 1
                        stats['failed_keys'].append({
                            'name': cert.corresponding_key,
                            'certificate': cert.name,
                            'partition': cert.partition,
                            'reason': 'Key deletion failed'
                        })
                else:
                    stats['failed_delete'] += 1
                    stats['failed_certificates'].append({
                        'name': cert.name,
                        'full_path': cert.full_path,
                        'partition': cert.partition,
                        'type': 'unused_certificate',
                        'reason': 'Certificate deletion failed',
                        'corresponding_key': cert.corresponding_key
                    })
        
        # Handle used expired certificates
        if report.used_expired:
            print(f"\n🔄 Processing {len(report.used_expired)} used expired certificates...")
            for cert, usage_list in report.used_expired:
                print(f"\n📋 Processing certificate: {cert.name}")
                
                # Dereference from all usage locations
                dereference_success = True
                successful_dereferences = []
                failed_dereferences = []
                
                for usage in usage_list:
                    if self.dereference_certificate(cert.full_path, usage):
                        stats['dereferenced'] += 1
                        successful_dereferences.append({
                            'object_type': usage.object_type,
                            'object_name': usage.object_name,
                            'object_path': usage.object_path,
                            'field_name': usage.field_name,
                            'partition': usage.partition
                        })
                    else:
                        stats['failed_dereference'] += 1
                        dereference_success = False
                        failed_dereferences.append({
                            'object_type': usage.object_type,
                            'object_name': usage.object_name,
                            'object_path': usage.object_path,
                            'field_name': usage.field_name,
                            'partition': usage.partition,
                            'reason': 'Dereference operation failed'
                        })
                
                # Track dereference results
                if successful_dereferences:
                    stats['successful_dereferences'].extend(successful_dereferences)
                if failed_dereferences:
                    stats['failed_dereferences'].extend(failed_dereferences)
                
                # Only delete if all dereferencing was successful
                if dereference_success:
                    print(f"  📋 Deleting dereferenced certificate: {cert.name} (partition: {cert.partition})")
                    cert_deleted, key_deleted = self.delete_certificate(cert.name, cert.corresponding_key, cert.partition)
                    if cert_deleted:
                        stats['deleted_used'] += 1
                        stats['successful_deletions'].append({
                            'name': cert.name,
                            'full_path': cert.full_path,
                            'partition': cert.partition,
                            'type': 'used_certificate',
                            'corresponding_key': cert.corresponding_key,
                            'dereferenced_from': successful_dereferences
                        })
                        if cert.corresponding_key and key_deleted:
                            stats['deleted_keys'] += 1
                        elif cert.corresponding_key and not key_deleted:
                            stats['failed_key_delete'] += 1
                            stats['failed_keys'].append({
                                'name': cert.corresponding_key,
                                'certificate': cert.name,
                                'partition': cert.partition,
                                'reason': 'Key deletion failed after successful certificate deletion'
                            })
                    else:
                        stats['failed_delete'] += 1
                        stats['failed_certificates'].append({
                            'name': cert.name,
                            'full_path': cert.full_path,
                            'partition': cert.partition,
                            'type': 'used_certificate',
                            'reason': 'Certificate deletion failed after successful dereferencing',
                            'corresponding_key': cert.corresponding_key,
                            'successful_dereferences': successful_dereferences
                        })
                else:
                    print(f"  ⚠️  Skipping deletion due to failed dereferencing")
                    stats['failed_certificates'].append({
                        'name': cert.name,
                        'full_path': cert.full_path,
                        'partition': cert.partition,
                        'type': 'used_certificate',
                        'reason': 'Skipped due to failed dereferencing',
                        'corresponding_key': cert.corresponding_key,
                        'failed_dereferences': failed_dereferences
                    })
        
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
    
    def is_default_certificate(self, cert_name: str, cert_path: str, cert_type: str = "") -> bool:
        """
        Check if a certificate is a default certificate that should never be deleted
        
        Args:
            cert_name: Certificate name
            cert_path: Certificate full path
            cert_type: Certificate type from F5 API (e.g., "Certificate Bundle")
            
        Returns:
            True if this is a default certificate, False otherwise
        """
        # Convert to lowercase for case-insensitive checking
        cert_name_lower = cert_name.lower()
        cert_path_lower = cert_path.lower()
        cert_type_lower = cert_type.lower()
        
        # PRIMARY RULE: Check certificate type first (most reliable)
        if 'bundle' in cert_type_lower:
            return True
        
        # SECONDARY RULE: Protect certificates with "default" in name/path
        if 'default' in cert_name_lower or 'default' in cert_path_lower:
            return True
        
        # FALLBACK RULE: Check for bundle in name/path (for older F5 versions or API limitations)
        if 'bundle' in cert_name_lower or 'bundle' in cert_path_lower:
            return True
        
        # Additional protection for common system certificate patterns
        system_patterns = [
            'system',
            'root-ca',
            'intermediate-ca',
            'chain',
            'ca-cert'
        ]
        
        for system_pattern in system_patterns:
            if system_pattern in cert_name_lower or system_pattern in cert_path_lower:
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
                
                # Check for trusted signing certificates in Client-SSL profiles
                ca_file = profile.get('caFile')
                if ca_file in cert_paths:
                    usage_map[ca_file].append(CertificateUsage(
                        object_type='Client-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='caFile (Trusted CA)',
                        partition=partition
                    ))
                
                # Check chainFile field for certificate chain
                chain_file = profile.get('chainFile')
                if chain_file in cert_paths:
                    usage_map[chain_file].append(CertificateUsage(
                        object_type='Client-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='chainFile (Certificate Chain)',
                        partition=partition
                    ))
                
                # Check trustedCertAuthorities field
                trusted_ca = profile.get('trustedCertAuthorities', [])
                if isinstance(trusted_ca, list):
                    for ca in trusted_ca:
                        if ca in cert_paths:
                            usage_map[ca].append(CertificateUsage(
                                object_type='Client-SSL Profile',
                                object_name=profile['name'],
                                object_path=profile['fullPath'],
                                field_name='trustedCertAuthorities (Trusted CA)',
                                partition=partition
                            ))
                elif trusted_ca in cert_paths:
                    usage_map[trusted_ca].append(CertificateUsage(
                        object_type='Client-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='trustedCertAuthorities (Trusted CA)',
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
                
                # Check for trusted signing certificates in Server-SSL profiles
                ca_file = profile.get('caFile')
                if ca_file in cert_paths:
                    usage_map[ca_file].append(CertificateUsage(
                        object_type='Server-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='caFile (Trusted CA)',
                        partition=partition
                    ))
                
                # Check chainFile field for certificate chain
                chain_file = profile.get('chainFile')
                if chain_file in cert_paths:
                    usage_map[chain_file].append(CertificateUsage(
                        object_type='Server-SSL Profile',
                        object_name=profile['name'],
                        object_path=profile['fullPath'],
                        field_name='chainFile (Certificate Chain)',
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
        
        # Check Certificate Validator Trust Stores
        try:
            print(f"    🔍 Checking Certificate Trust Stores...")
            response = self._make_request('GET', f'/mgmt/tm/sys/crypto/cert-validator/truststore?$filter=partition eq {partition}')
            for truststore in response.json().get('items', []):
                trusted_certs = truststore.get('trustedCerts', [])
                if isinstance(trusted_certs, list):
                    for trusted_cert in trusted_certs:
                        if trusted_cert in cert_paths:
                            usage_map[trusted_cert].append(CertificateUsage(
                                object_type='Certificate Trust Store',
                                object_name=truststore['name'],
                                object_path=truststore['fullPath'],
                                field_name='trustedCerts (Trust Store)',
                                partition=partition
                            ))
                elif trusted_certs in cert_paths:
                    usage_map[trusted_certs].append(CertificateUsage(
                        object_type='Certificate Trust Store',
                        object_name=truststore['name'],
                        object_path=truststore['fullPath'],
                        field_name='trustedCerts (Trust Store)',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check Certificate Trust Stores in partition {partition}: {e}")
        
        # Check HTTP profiles for trusted certificates
        try:
            print(f"    🔍 Checking HTTP profiles...")
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/http?$filter=partition eq {partition}')
            for http_profile in response.json().get('items', []):
                # Check for SSL client certificates in HTTP profiles
                trusted_ca = http_profile.get('trustedCertAuthorities')
                if trusted_ca in cert_paths:
                    usage_map[trusted_ca].append(CertificateUsage(
                        object_type='HTTP Profile',
                        object_name=http_profile['name'],
                        object_path=http_profile['fullPath'],
                        field_name='trustedCertAuthorities (HTTP Profile)',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check HTTP profiles in partition {partition}: {e}")
            
        # Check WebAcceleration profiles
        try:
            print(f"    🔍 Checking Web Acceleration profiles...")
            response = self._make_request('GET', f'/mgmt/tm/ltm/profile/web-acceleration?$filter=partition eq {partition}')
            for wa_profile in response.json().get('items', []):
                ca_cert = wa_profile.get('sslCaCertFile')
                if ca_cert in cert_paths:
                    usage_map[ca_cert].append(CertificateUsage(
                        object_type='Web Acceleration Profile',
                        object_name=wa_profile['name'],
                        object_path=wa_profile['fullPath'],
                        field_name='sslCaCertFile (Web Acceleration)',
                        partition=partition
                    ))
        except Exception as e:
            print(f"    ⚠️  Warning: Could not check Web Acceleration profiles in partition {partition}: {e}")
    
    def get_running_config(self) -> Dict[str, any]:
        """
        Get the current running configuration from the F5 device using show running-config command
        
        Returns:
            Dictionary containing the running configuration
        """
        try:
            print("📥 Retrieving running configuration...")
            
            # Use F5's command execution API to run 'show running-config'
            command_data = {
                "command": "run",
                "utilCmdArgs": "-c 'show running-config'"
            }
            
            response = self._make_request('POST', '/mgmt/tm/util/bash', json=command_data)
            result = response.json()
            
            # Extract the command output
            raw_config_text = result.get('commandResult', '')
            
            # Create comprehensive configuration snapshot
            sections = {
                'timestamp': datetime.datetime.now().isoformat(),
                'device_hostname': self.original_host,
                'raw_config_text': raw_config_text,
                'ssl_profiles': {},
                'monitors': {},
                'certificates': {},
                'virtual_servers': {},
                'gtm_objects': {}
            }
            
            # Get SSL profiles for detailed tracking
            try:
                client_ssl_response = self._make_request('GET', '/mgmt/tm/ltm/profile/client-ssl')
                sections['ssl_profiles']['client_ssl'] = client_ssl_response.json().get('items', [])
            except Exception as e:
                print(f"  ⚠️  Warning: Could not retrieve Client-SSL profiles: {e}")
                sections['ssl_profiles']['client_ssl'] = []
            
            try:
                server_ssl_response = self._make_request('GET', '/mgmt/tm/ltm/profile/server-ssl')
                sections['ssl_profiles']['server_ssl'] = server_ssl_response.json().get('items', [])
            except Exception as e:
                print(f"  ⚠️  Warning: Could not retrieve Server-SSL profiles: {e}")
                sections['ssl_profiles']['server_ssl'] = []
            
            # Get monitors
            try:
                ltm_monitors_response = self._make_request('GET', '/mgmt/tm/ltm/monitor/https')
                sections['monitors']['ltm_https'] = ltm_monitors_response.json().get('items', [])
            except Exception as e:
                print(f"  ⚠️  Warning: Could not retrieve LTM HTTPS monitors: {e}")
                sections['monitors']['ltm_https'] = []
            
            if self.is_gtm_available():
                try:
                    gtm_monitors_response = self._make_request('GET', '/mgmt/tm/gtm/monitor/https')
                    sections['monitors']['gtm_https'] = gtm_monitors_response.json().get('items', [])
                except Exception as e:
                    print(f"  ⚠️  Warning: Could not retrieve GTM HTTPS monitors: {e}")
                    sections['monitors']['gtm_https'] = []
            else:
                sections['monitors']['gtm_https'] = []
            
            # Get certificates
            try:
                certs_response = self._make_request('GET', '/mgmt/tm/sys/file/ssl-cert')
                sections['certificates'] = certs_response.json().get('items', [])
            except Exception as e:
                print(f"  ⚠️  Warning: Could not retrieve SSL certificates: {e}")
                sections['certificates'] = []
            
            # Get Virtual Servers from all partitions
            try:
                partitions = self.discover_partitions()
                all_virtual_servers = []
                for partition in partitions:
                    try:
                        vs_response = self._make_request('GET', f'/mgmt/tm/ltm/virtual?$filter=partition eq {partition}')
                        partition_vs = vs_response.json().get('items', [])
                        all_virtual_servers.extend(partition_vs)
                    except Exception as e:
                        print(f"  ⚠️  Warning: Could not retrieve Virtual Servers from partition {partition}: {e}")
                sections['virtual_servers'] = all_virtual_servers
            except Exception as e:
                print(f"  ⚠️  Warning: Could not retrieve Virtual Servers: {e}")
                sections['virtual_servers'] = []
            
            # Calculate configuration size for validation
            config_size = len(raw_config_text) if raw_config_text else 0
            sections['config_size'] = config_size
            
            if config_size > 0:
                print(f"✅ Running configuration retrieved successfully ({config_size:,} characters)")
            else:
                print(f"⚠️  Warning: Running configuration appears to be empty")
            
            return sections
            
        except Exception as e:
            print(f"❌ Failed to retrieve running configuration: {e}")
            print(f"   Trying fallback method...")
            
            # Fallback: Try alternative command execution method
            try:
                # Alternative method using tmsh command
                command_data = {
                    "command": "run",
                    "utilCmdArgs": "-c 'tmsh show running-config'"
                }
                
                response = self._make_request('POST', '/mgmt/tm/util/bash', json=command_data)
                result = response.json()
                raw_config_text = result.get('commandResult', '')
                
                if raw_config_text:
                    print(f"✅ Running configuration retrieved using fallback method")
                    return {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'device_hostname': self.original_host,
                        'raw_config_text': raw_config_text,
                        'config_size': len(raw_config_text),
                        'method': 'fallback_tmsh',
                        'ssl_profiles': {'client_ssl': [], 'server_ssl': []},
                        'monitors': {'ltm_https': [], 'gtm_https': []},
                        'certificates': [],
                        'virtual_servers': []
                    }
                else:
                    raise Exception("Fallback method also returned empty configuration")
                    
            except Exception as fallback_error:
                print(f"❌ Fallback method also failed: {fallback_error}")
                return {
                    'error': str(e), 
                    'fallback_error': str(fallback_error),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'device_hostname': self.original_host,
                    'raw_config_text': '',
                    'config_size': 0,
                    'ssl_profiles': {'client_ssl': [], 'server_ssl': []},
                    'monitors': {'ltm_https': [], 'gtm_https': []},
                    'certificates': [],
                    'virtual_servers': []
                }
    
    def save_running_config(self, config: Dict[str, any], filename: str = None) -> str:
        """
        Save running configuration to a JSON file
        
        Args:
            config: Configuration dictionary
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            Path to saved configuration file
        """
        try:
            if filename is None:
                # Auto-generate filename with device IP and timestamp
                device_ip = self.original_host.replace('https://', '').replace('http://', '').replace(':', '_').replace('.', '_')
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"config_{device_ip}_{timestamp}.json"
            
            # Check if configuration contains error
            if 'error' in config:
                print(f"⚠️  Warning: Configuration contains error information")
                if 'raw_config_text' not in config or not config['raw_config_text']:
                    print(f"⚠️  Warning: No configuration text retrieved")
            else:
                # Validate configuration size
                config_size = config.get('config_size', 0)
                if config_size == 0:
                    print(f"⚠️  Warning: Configuration appears to be empty")
                else:
                    print(f"ℹ️  Configuration size: {config_size:,} characters")
            
            # Save configuration to file
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, default=str)
            
            print(f"💾 Running configuration saved to: {filename}")
            return filename
            
        except Exception as e:
            print(f"❌ Failed to save running configuration: {e}")
            return ""
    
    def generate_config_diff_html(self, pre_config: Dict[str, any], post_config: Dict[str, any], 
                                 cleanup_stats: Dict[str, any] = None, output_file: str = None) -> str:
        """
        Generate an HTML diff report comparing pre and post configurations
        
        Args:
            pre_config: Configuration before cleanup
            post_config: Configuration after cleanup
            cleanup_stats: Statistics and details from cleanup execution
            output_file: Optional output filename
            
        Returns:
            Path to generated HTML diff file
        """
        try:
            if output_file is None:
                # Auto-generate filename with device IP
                device_ip = self.original_host.replace('https://', '').replace('http://', '').replace(':', '_').replace('.', '_')
                output_file = f"diff_{device_ip}.html"
            
            # Generate diff analysis
            changes = self._analyze_config_changes(pre_config, post_config)
            
            # Generate HTML content
            html_content = self._generate_diff_html_content(changes, pre_config, post_config, cleanup_stats)
            
            # Write HTML file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"📄 Configuration diff report generated: {output_file}")
            return output_file
            
        except Exception as e:
            print(f"❌ Failed to generate configuration diff: {e}")
            return ""
    
    def _analyze_config_changes(self, pre_config: Dict[str, any], post_config: Dict[str, any]) -> Dict[str, any]:
        """
        Analyze changes between pre and post configurations
        
        Args:
            pre_config: Configuration before cleanup
            post_config: Configuration after cleanup
            
        Returns:
            Dictionary containing analysis of changes
        """
        changes = {
            'certificates_deleted': [],
            'ssl_profiles_modified': [],
            'monitors_modified': [],
            'summary': {
                'total_changes': 0,
                'certificates_removed': 0,
                'profiles_updated': 0,
                'monitors_updated': 0
            }
        }
        
        # Compare certificates
        pre_certs = {cert.get('name'): cert for cert in pre_config.get('certificates', [])}
        post_certs = {cert.get('name'): cert for cert in post_config.get('certificates', [])}
        
        for cert_name in pre_certs:
            if cert_name not in post_certs:
                changes['certificates_deleted'].append({
                    'name': cert_name,
                    'fullPath': pre_certs[cert_name].get('fullPath', ''),
                    'expirationDate': pre_certs[cert_name].get('expirationDate', ''),
                    'subject': pre_certs[cert_name].get('subject', '')
                })
                changes['summary']['certificates_removed'] += 1
        
        # Compare SSL profiles
        self._compare_ssl_profiles(pre_config, post_config, changes)
        
        # Compare monitors
        self._compare_monitors(pre_config, post_config, changes)
        
        # Calculate total changes
        changes['summary']['total_changes'] = (
            changes['summary']['certificates_removed'] + 
            changes['summary']['profiles_updated'] + 
            changes['summary']['monitors_updated']
        )
        
        return changes
    
    def _compare_ssl_profiles(self, pre_config: Dict[str, any], post_config: Dict[str, any], 
                            changes: Dict[str, any]) -> None:
        """Compare SSL profiles between pre and post configurations"""
        
        # Compare Client-SSL profiles
        pre_client_ssl = {p.get('name'): p for p in pre_config.get('ssl_profiles', {}).get('client_ssl', [])}
        post_client_ssl = {p.get('name'): p for p in post_config.get('ssl_profiles', {}).get('client_ssl', [])}
        
        for profile_name in pre_client_ssl:
            if profile_name in post_client_ssl:
                pre_profile = pre_client_ssl[profile_name]
                post_profile = post_client_ssl[profile_name]
                
                # Compare cert key chains
                pre_chains = pre_profile.get('certKeyChain', [])
                post_chains = post_profile.get('certKeyChain', [])
                
                if pre_chains != post_chains:
                    changes['ssl_profiles_modified'].append({
                        'type': 'Client-SSL Profile',
                        'name': profile_name,
                        'fullPath': pre_profile.get('fullPath', ''),
                        'changes': {
                            'certKeyChain': {
                                'before': pre_chains,
                                'after': post_chains
                            }
                        }
                    })
                    changes['summary']['profiles_updated'] += 1
        
        # Compare Server-SSL profiles
        pre_server_ssl = {p.get('name'): p for p in pre_config.get('ssl_profiles', {}).get('server_ssl', [])}
        post_server_ssl = {p.get('name'): p for p in post_config.get('ssl_profiles', {}).get('server_ssl', [])}
        
        for profile_name in pre_server_ssl:
            if profile_name in post_server_ssl:
                pre_profile = pre_server_ssl[profile_name]
                post_profile = post_server_ssl[profile_name]
                
                # Compare cert and key fields
                cert_changed = pre_profile.get('cert') != post_profile.get('cert')
                key_changed = pre_profile.get('key') != post_profile.get('key')
                
                if cert_changed or key_changed:
                    profile_changes = {}
                    if cert_changed:
                        profile_changes['cert'] = {
                            'before': pre_profile.get('cert'),
                            'after': post_profile.get('cert')
                        }
                    if key_changed:
                        profile_changes['key'] = {
                            'before': pre_profile.get('key'),
                            'after': post_profile.get('key')
                        }
                    
                    changes['ssl_profiles_modified'].append({
                        'type': 'Server-SSL Profile',
                        'name': profile_name,
                        'fullPath': pre_profile.get('fullPath', ''),
                        'changes': profile_changes
                    })
                    changes['summary']['profiles_updated'] += 1
    
    def _compare_monitors(self, pre_config: Dict[str, any], post_config: Dict[str, any], 
                         changes: Dict[str, any]) -> None:
        """Compare monitors between pre and post configurations"""
        
        # Compare LTM HTTPS monitors
        pre_ltm_monitors = {m.get('name'): m for m in pre_config.get('monitors', {}).get('ltm_https', [])}
        post_ltm_monitors = {m.get('name'): m for m in post_config.get('monitors', {}).get('ltm_https', [])}
        
        for monitor_name in pre_ltm_monitors:
            if monitor_name in post_ltm_monitors:
                pre_monitor = pre_ltm_monitors[monitor_name]
                post_monitor = post_ltm_monitors[monitor_name]
                
                if pre_monitor.get('cert') != post_monitor.get('cert'):
                    changes['monitors_modified'].append({
                        'type': 'LTM HTTPS Monitor',
                        'name': monitor_name,
                        'fullPath': pre_monitor.get('fullPath', ''),
                        'changes': {
                            'cert': {
                                'before': pre_monitor.get('cert'),
                                'after': post_monitor.get('cert')
                            }
                        }
                    })
                    changes['summary']['monitors_updated'] += 1
        
        # Compare GTM HTTPS monitors
        pre_gtm_monitors = {m.get('name'): m for m in pre_config.get('monitors', {}).get('gtm_https', [])}
        post_gtm_monitors = {m.get('name'): m for m in post_config.get('monitors', {}).get('gtm_https', [])}
        
        for monitor_name in pre_gtm_monitors:
            if monitor_name in post_gtm_monitors:
                pre_monitor = pre_gtm_monitors[monitor_name]
                post_monitor = post_gtm_monitors[monitor_name]
                
                if pre_monitor.get('cert') != post_monitor.get('cert'):
                    changes['monitors_modified'].append({
                        'type': 'GTM HTTPS Monitor',
                        'name': monitor_name,
                        'fullPath': pre_monitor.get('fullPath', ''),
                        'changes': {
                            'cert': {
                                'before': pre_monitor.get('cert'),
                                'after': post_monitor.get('cert')
                            }
                        }
                    })
                    changes['summary']['monitors_updated'] += 1
    
    def _generate_running_config_diff(self, pre_config: Dict[str, any], post_config: Dict[str, any]) -> str:
        """
        Generate a side-by-side diff of the running configuration text
        
        Args:
            pre_config: Configuration before cleanup
            post_config: Configuration after cleanup
            
        Returns:
            HTML formatted side-by-side diff content
        """
        try:
            # Get the raw configuration text
            pre_config_text = pre_config.get('raw_config_text', '')
            post_config_text = post_config.get('raw_config_text', '')
            
            if not pre_config_text or not post_config_text:
                return '<div class="no-diff">No running configuration text available for comparison</div>'
            
            # Split into lines for difflib
            pre_lines = pre_config_text.splitlines()
            post_lines = post_config_text.splitlines()
            
            # Check if there are any differences
            if pre_lines == post_lines:
                return '<div class="no-changes-diff">No changes detected in running configuration</div>'
            
            # Generate side-by-side HTML diff
            differ = difflib.HtmlDiff(wrapcolumn=70)
            side_by_side_html = differ.make_table(
                pre_lines,
                post_lines,
                fromdesc='Configuration BEFORE Cleanup',
                todesc='Configuration AFTER Cleanup',
                context=True,
                numlines=3
            )
            
            # Wrap in our custom styling div
            return f'<div class="side-by-side-diff">{side_by_side_html}</div>'
            
        except Exception as e:
            return f'<div class="diff-error">Error generating side-by-side config diff: {str(e)}</div>'
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        import html
        return html.escape(text)

    def _generate_diff_html_content(self, changes: Dict[str, any], pre_config: Dict[str, any], 
                                   post_config: Dict[str, any], cleanup_stats: Dict[str, any] = None) -> str:
        """Generate HTML content for the configuration diff report"""
        
        device_info = pre_config.get('device_hostname', 'Unknown Device')
        pre_timestamp = pre_config.get('timestamp', 'Unknown')
        post_timestamp = post_config.get('timestamp', 'Unknown')
        
        # Configuration size information
        pre_size = pre_config.get('config_size', 0)
        post_size = post_config.get('config_size', 0)
        config_method = pre_config.get('method', 'standard')
        
        # Generate running config diff
        running_config_diff = self._generate_running_config_diff(pre_config, post_config)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>F5 Configuration Diff Report - {device_info}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 6px; margin-bottom: 30px; border-left: 4px solid #28a745; }}
        .summary h2 {{ margin: 0 0 15px 0; color: #28a745; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .summary-item {{ text-align: center; }}
        .summary-number {{ font-size: 32px; font-weight: bold; color: #495057; }}
        .summary-label {{ color: #6c757d; font-size: 14px; }}
        .section {{ margin-bottom: 30px; }}
        .section h3 {{ color: #495057; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }}
        .change-item {{ background: #fff; border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 15px; padding: 20px; }}
        .change-header {{ font-weight: bold; color: #495057; margin-bottom: 10px; }}
        .change-path {{ color: #6c757d; font-size: 14px; margin-bottom: 15px; }}
        .change-details {{ font-family: monospace; background: #f8f9fa; padding: 15px; border-radius: 4px; }}
        .before {{ color: #dc3545; background: #f8d7da; padding: 8px; border-radius: 4px; margin: 5px 0; }}
        .after {{ color: #28a745; background: #d4edda; padding: 8px; border-radius: 4px; margin: 5px 0; }}
        .no-changes {{ text-align: center; color: #6c757d; padding: 40px; }}
        .timestamp {{ font-size: 12px; color: #6c757d; }}
        .cert-info {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 14px; }}
        
        /* Side-by-side diff styling */
        .side-by-side-diff {{ 
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; 
            font-size: 12px; 
            border: 1px solid #d1d9e0; 
            border-radius: 6px; 
            background: #f6f8fa; 
            margin: 20px 0;
            overflow-x: auto;
        }}
        .side-by-side-diff table {{ 
            width: 100%; 
            border-collapse: collapse; 
            font-family: inherit; 
            font-size: inherit;
        }}
        .side-by-side-diff th {{ 
            background-color: #f1f8ff; 
            color: #24292e; 
            padding: 8px 12px; 
            border-bottom: 1px solid #c6cbd1; 
            font-weight: bold; 
            text-align: center;
        }}
        .side-by-side-diff td {{ 
            padding: 2px 8px; 
            vertical-align: top; 
            white-space: pre-wrap; 
            word-break: break-all;
            border: none;
        }}
        .side-by-side-diff .diff_header {{ 
            background-color: #f1f8ff !important; 
            color: #24292e !important; 
            text-align: center !important; 
            font-weight: bold !important;
        }}
        .side-by-side-diff .diff_next {{ 
            background-color: #f6f8fa !important; 
            border-right: 1px solid #d1d9e0 !important; 
            width: 1% !important; 
            text-align: center !important;
        }}
        .side-by-side-diff .diff_add {{ 
            background-color: #e6ffed !important; 
            border-right: 1px solid #c6cbd1 !important;
        }}
        .side-by-side-diff .diff_chg {{ 
            background-color: #fff5b4 !important; 
            border-right: 1px solid #c6cbd1 !important;
        }}
        .side-by-side-diff .diff_sub {{ 
            background-color: #ffeef0 !important; 
            border-right: 1px solid #c6cbd1 !important;
        }}
        .side-by-side-diff .diff_context {{ 
            background-color: #fff !important; 
            border-right: 1px solid #e1e4e8 !important;
        }}
        .side-by-side-diff tr:hover {{ 
            background-color: rgba(255, 212, 59, 0.1) !important; 
        }}
        .no-diff, .no-changes-diff {{ 
            text-align: center; 
            color: #6c757d; 
            padding: 40px; 
            font-style: italic; 
        }}
        .diff-error {{ 
            background-color: #ffeef0; 
            border: 1px solid #f97583; 
            color: #d73a49; 
            padding: 16px; 
            border-radius: 6px; 
            margin: 20px 0; 
        }}
        .diff-stats {{ 
            background-color: #f6f8fa; 
            border: 1px solid #d1d9e0; 
            border-radius: 6px; 
            padding: 16px; 
            margin: 20px 0; 
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; 
            font-size: 12px; 
        }}
        .file-header {{ 
            background-color: #f6f8fa; 
            border-bottom: 1px solid #d1d9e0; 
            padding: 8px 16px; 
            font-weight: bold; 
            color: #24292e; 
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 F5 Configuration Diff Report</h1>
            <p>Certificate Cleanup Impact Analysis for {device_info}</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <h2>📊 Summary of Changes</h2>
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-number">{changes['summary']['total_changes']}</div>
                        <div class="summary-label">Total Changes</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{changes['summary']['certificates_removed']}</div>
                        <div class="summary-label">Certificates Deleted</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{changes['summary']['profiles_updated']}</div>
                        <div class="summary-label">SSL Profiles Updated</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{changes['summary']['monitors_updated']}</div>
                        <div class="summary-label">Monitors Updated</div>
                    </div>
                </div>
                <div style="margin-top: 20px;">
                    <div class="timestamp">Pre-cleanup: {pre_timestamp} ({pre_size:,} chars)</div>
                    <div class="timestamp">Post-cleanup: {post_timestamp} ({post_size:,} chars)</div>
                    <div class="timestamp">Configuration method: {config_method}</div>
                </div>
            </div>
            
        """
        
        # Add cleanup failures section if cleanup_stats is provided
        if cleanup_stats:
            html_content += f"""
            <div class="section">
                <h3>⚠️ Cleanup Operation Results</h3>
                <div class="summary" style="background: #f8f9fa; border-left: 4px solid #007acc;">
                    <h4>📊 Operation Summary</h4>
                    <div class="summary-grid">
                        <div class="summary-item">
                            <div class="summary-number" style="color: #28a745;">{cleanup_stats.get('deleted_unused', 0) + cleanup_stats.get('deleted_used', 0)}</div>
                            <div class="summary-label">Certificates Deleted</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-number" style="color: #28a745;">{cleanup_stats.get('deleted_keys', 0)}</div>
                            <div class="summary-label">Keys Deleted</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-number" style="color: #28a745;">{cleanup_stats.get('dereferenced', 0)}</div>
                            <div class="summary-label">Successful Dereferences</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-number" style="color: #dc3545;">{len(cleanup_stats.get('failed_certificates', []))}</div>
                            <div class="summary-label">Failed Certificate Deletions</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-number" style="color: #dc3545;">{len(cleanup_stats.get('failed_keys', []))}</div>
                            <div class="summary-label">Failed Key Deletions</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-number" style="color: #dc3545;">{len(cleanup_stats.get('failed_dereferences', []))}</div>
                            <div class="summary-label">Failed Dereferences</div>
                        </div>
                    </div>
                </div>
            """
            
            # Add failed certificates section
            failed_certs = cleanup_stats.get('failed_certificates', [])
            if failed_certs:
                html_content += """
                <h4 style="color: #dc3545;">❌ Failed Certificate Deletions</h4>
                <table class="cert-table">
                    <thead>
                        <tr>
                            <th>Certificate Name</th>
                            <th>Partition</th>
                            <th>Type</th>
                            <th>Reason</th>
                            <th>Corresponding Key</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for cert in failed_certs:
                    html_content += f"""
                        <tr class="expired">
                            <td>{cert['name']}</td>
                            <td>{cert['partition']}</td>
                            <td>{cert['type'].replace('_', ' ').title()}</td>
                            <td>{cert['reason']}</td>
                            <td>{cert.get('corresponding_key', 'N/A')}</td>
                        </tr>
                    """
                html_content += """
                    </tbody>
                </table>
                """
            
            # Add failed keys section
            failed_keys = cleanup_stats.get('failed_keys', [])
            if failed_keys:
                html_content += """
                <h4 style="color: #dc3545;">🔑 Failed Key Deletions</h4>
                <table class="cert-table">
                    <thead>
                        <tr>
                            <th>Key Name</th>
                            <th>Certificate</th>
                            <th>Partition</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for key in failed_keys:
                    html_content += f"""
                        <tr class="expired">
                            <td>{key['name']}</td>
                            <td>{key['certificate']}</td>
                            <td>{key['partition']}</td>
                            <td>{key['reason']}</td>
                        </tr>
                    """
                html_content += """
                    </tbody>
                </table>
                """
            
            # Add failed dereferences section
            failed_derefs = cleanup_stats.get('failed_dereferences', [])
            if failed_derefs:
                html_content += """
                <h4 style="color: #dc3545;">🔄 Failed Dereference Operations</h4>
                <table class="cert-table">
                    <thead>
                        <tr>
                            <th>Object Type</th>
                            <th>Object Name</th>
                            <th>Partition</th>
                            <th>Field</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for deref in failed_derefs:
                    html_content += f"""
                        <tr class="expired">
                            <td>{deref['object_type']}</td>
                            <td>{deref['object_name']}</td>
                            <td>{deref['partition']}</td>
                            <td>{deref['field_name']}</td>
                            <td>{deref['reason']}</td>
                        </tr>
                    """
                html_content += """
                    </tbody>
                </table>
                """
            
            # If no failures, show success message
            if not failed_certs and not failed_keys and not failed_derefs:
                html_content += """
                <div style="background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; border: 1px solid #c3e6cb;">
                    <h4 style="color: #155724; margin: 0;">✅ All Operations Completed Successfully</h4>
                    <p style="margin: 10px 0 0 0;">No failures occurred during the certificate cleanup process.</p>
                </div>
                """
            
            html_content += "</div>"
        
        # Add running config diff section
        html_content += f"""
            <div class="section">
                <h3>📄 Running Configuration Changes</h3>
                <div class="file-header">
                    F5 Running Configuration Diff (show running-config)
                </div>
                {running_config_diff}
            </div>
        """
        
        # Add certificates deleted section
        if changes['certificates_deleted']:
            html_content += """
            <div class="section">
                <h3>🗑️ Certificates Deleted</h3>
            """
            for cert in changes['certificates_deleted']:
                exp_date = 'Unknown'
                if cert.get('expirationDate'):
                    try:
                        exp_date = datetime.datetime.fromtimestamp(cert['expirationDate']).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        exp_date = str(cert['expirationDate'])
                
                html_content += f"""
                <div class="change-item">
                    <div class="change-header">🔒 {cert['name']}</div>
                    <div class="change-path">{cert['fullPath']}</div>
                    <div class="cert-info">
                        <div><strong>Subject:</strong> {cert.get('subject', 'N/A')}</div>
                        <div><strong>Expiration:</strong> {exp_date}</div>
                    </div>
                </div>
                """
            html_content += "</div>"
        
        # Add SSL profiles modified section
        if changes['ssl_profiles_modified']:
            html_content += """
            <div class="section">
                <h3>🔧 SSL Profiles Modified</h3>
            """
            for profile in changes['ssl_profiles_modified']:
                html_content += f"""
                <div class="change-item">
                    <div class="change-header">⚙️ {profile['type']}: {profile['name']}</div>
                    <div class="change-path">{profile['fullPath']}</div>
                    <div class="change-details">
                """
                
                for field, change in profile['changes'].items():
                    if field == 'certKeyChain':
                        html_content += f"<strong>{field}:</strong><br/>"
                        html_content += f'<div class="before">Before: {json.dumps(change["before"], indent=2)}</div>'
                        html_content += f'<div class="after">After: {json.dumps(change["after"], indent=2)}</div>'
                    else:
                        html_content += f'<strong>{field}:</strong><br/>'
                        html_content += f'<div class="before">Before: {change["before"]}</div>'
                        html_content += f'<div class="after">After: {change["after"]}</div>'
                
                html_content += """
                    </div>
                </div>
                """
            html_content += "</div>"
        
        # Add monitors modified section
        if changes['monitors_modified']:
            html_content += """
            <div class="section">
                <h3>📡 Monitors Modified</h3>
            """
            for monitor in changes['monitors_modified']:
                html_content += f"""
                <div class="change-item">
                    <div class="change-header">📊 {monitor['type']}: {monitor['name']}</div>
                    <div class="change-path">{monitor['fullPath']}</div>
                    <div class="change-details">
                """
                
                for field, change in monitor['changes'].items():
                    html_content += f'<strong>{field}:</strong><br/>'
                    html_content += f'<div class="before">Before: {change["before"]}</div>'
                    html_content += f'<div class="after">After: {change["after"]}</div>'
                
                html_content += """
                    </div>
                </div>
                """
            html_content += "</div>"
        
        # No changes section
        if changes['summary']['total_changes'] == 0:
            html_content += """
            <div class="no-changes">
                <h3>✅ No Configuration Changes Detected</h3>
                <p>The certificate cleanup operation did not result in any configuration changes.</p>
            </div>
            """
        
        html_content += """
        </div>
    </div>
</body>
</html>
        """
        
        return html_content

def process_multiple_devices(devices: List[DeviceInfo], username: str = "", password: str = "", 
                           expiry_days: int = 30, report_only: bool = False, 
                           use_bulk_optimization: bool = True) -> BatchCleanupReport:
    """
    Process certificate cleanup for multiple F5 devices
    
    Args:
        devices: List of DeviceInfo objects
        username: Default username if not specified in CSV
        password: Default password if not specified in CSV  
        expiry_days: Days ahead to consider certificates as expiring
        report_only: Whether to only generate reports without cleanup
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
            generated_report_file = f5_cleanup.generate_html_report(report, report_file)
            
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
            
            # 🔍 PRE-CHECK: Save running configuration before any changes
            print(f"\n🔍 Pre-cleanup configuration check...")
            pre_config = f5_cleanup.get_running_config()
            pre_config_file = f5_cleanup.save_running_config(pre_config, None)
            
            # Ask for user confirmation
            print(f"\n⚠️  This will delete {len(report.expired_certificates)} expired certificate(s)")
            print(f"   - {len(report.unused_expired)} will be deleted directly")
            print(f"   - {len(report.used_expired)} will be dereferenced first")
            print(f"\n📥 Pre-cleanup configuration saved to: {pre_config_file}")
            
            confirm = input("\n❓ Do you want to proceed with the cleanup? (yes/no): ").lower().strip()
            
            if confirm != 'yes':
                print("❌ Cleanup cancelled by user")
                return
            
            # Execute cleanup
            stats = f5_cleanup.execute_cleanup(report)
            
            # 🔍 POST-CHECK: Save running configuration after changes and generate diff
            print(f"\n🔍 Post-cleanup configuration check...")
            post_config = f5_cleanup.get_running_config()
            post_config_file = f5_cleanup.save_running_config(post_config, None)
            
            # Generate configuration diff report
            print(f"\n📊 Generating configuration diff report...")
            diff_report_file = f5_cleanup.generate_config_diff_html(pre_config, post_config, stats)
            
            # Print final results
            print(f"\n🎉 Cleanup completed!")
            print(f"  ✅ Deleted unused certificates: {stats['deleted_unused']}")
            print(f"  ✅ Deleted used certificates: {stats['deleted_used']}")
            print(f"  🔑 Deleted SSL keys: {stats['deleted_keys']}")
            print(f"  🔄 Dereferenced objects: {stats['dereferenced']}")
            
            # Show detailed failure information if any failures occurred
            failed_certs = len(stats.get('failed_certificates', []))
            failed_keys = len(stats.get('failed_keys', []))
            failed_derefs = len(stats.get('failed_dereferences', []))
            
            if failed_certs or failed_keys or failed_derefs:
                print(f"\n⚠️  Cleanup Issues:")
                if failed_certs:
                    print(f"  ❌ Failed certificate deletions: {failed_certs}")
                    for cert in stats.get('failed_certificates', []):
                        print(f"    - {cert['name']} ({cert['partition']}): {cert['reason']}")
                if failed_keys:
                    print(f"  ❌ Failed key deletions: {failed_keys}")
                    for key in stats.get('failed_keys', []):
                        print(f"    - {key['name']} (cert: {key['certificate']}): {key['reason']}")
                if failed_derefs:
                    print(f"  ❌ Failed dereferences: {failed_derefs}")
                    for deref in stats.get('failed_dereferences', []):
                        print(f"    - {deref['object_type']} {deref['object_name']}: {deref['reason']}")
                print(f"\n💡 Check the configuration diff report for detailed failure analysis.")
            
            # Print file locations
            print(f"\n📁 Generated Files:")
            print(f"  📄 Certificate cleanup report: {generated_report_file}")
            print(f"  📥 Pre-cleanup configuration: {pre_config_file}")
            print(f"  📤 Post-cleanup configuration: {post_config_file}")
            if diff_report_file:
                print(f"  🔍 Configuration diff report: {diff_report_file}")
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 