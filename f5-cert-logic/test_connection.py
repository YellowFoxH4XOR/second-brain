#!/usr/bin/env python3
"""
F5 BIG-IP Connection Test Script

Simple script to test connectivity and permissions to F5 BIG-IP device
before running the main certificate cleanup script.

Usage:
    python test_connection.py --host 192.168.1.100 --username admin
"""

import requests
import urllib3
import argparse
import getpass
import sys
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_standard_session():
    """Create a standard requests session for F5 communication"""
    session = requests.Session()
    session.verify = False
    session.timeout = (10, 30)  # (connect_timeout, read_timeout)
    return session

def test_f5_connection(host, username, password):
    """Test F5 BIG-IP connectivity and permissions"""
    
    if not host.startswith('https://'):
        host = f"https://{host}"
    
    auth = (username, password)
    
    # Create standard session
    session = create_standard_session()
    session.auth = auth
    print("🔒 Using standard TLS configuration")
    
    print(f"🔌 Testing connection to F5 BIG-IP: {host}")
    print("=" * 60)
    
    tests = [
        {
            'name': 'Basic Authentication',
            'endpoint': '/mgmt/tm/sys/version',
            'description': 'Test basic API access and authentication'
        },
        {
            'name': 'Certificate Management Access',
            'endpoint': '/mgmt/tm/sys/file/ssl-cert',
            'description': 'Test access to SSL certificate management'
        },
        {
            'name': 'SSL Key Management Access',
            'endpoint': '/mgmt/tm/sys/file/ssl-key',
            'description': 'Test access to SSL key management'
        },
        {
            'name': 'Client-SSL Profile Access',
            'endpoint': '/mgmt/tm/ltm/profile/client-ssl',
            'description': 'Test access to Client-SSL profiles'
        },
        {
            'name': 'Server-SSL Profile Access',
            'endpoint': '/mgmt/tm/ltm/profile/server-ssl',
            'description': 'Test access to Server-SSL profiles'
        },
        {
            'name': 'LTM Monitor Access',
            'endpoint': '/mgmt/tm/ltm/monitor/https',
            'description': 'Test access to LTM HTTPS monitors'
        },
        {
            'name': 'GTM Monitor Access',
            'endpoint': '/mgmt/tm/gtm/monitor/https',
            'description': 'Test access to GTM HTTPS monitors (may not exist on all systems)'
        },
        {
            'name': 'OCSP Responder Access',
            'endpoint': '/mgmt/tm/sys/crypto/cert-validator/ocsp',
            'description': 'Test access to OCSP responders'
        },
        {
            'name': 'APM Authentication Profile Access',
            'endpoint': '/mgmt/tm/apm/profile/authentication',
            'description': 'Test access to APM authentication profiles (may not exist on all systems)'
        },
        {
            'name': 'LDAP Server Access',
            'endpoint': '/mgmt/tm/auth/ldap',
            'description': 'Test access to LDAP authentication servers'
        },
        {
            'name': 'RADIUS Server Access',
            'endpoint': '/mgmt/tm/auth/radius-server',
            'description': 'Test access to RADIUS authentication servers'
        },
        {
            'name': 'Syslog Configuration Access',
            'endpoint': '/mgmt/tm/sys/syslog',
            'description': 'Test access to Syslog configuration'
        }
    ]
    
    results = []
    
    # Test initial connection
    try:
        response = session.get(f"{host}/mgmt/tm/sys/version")
        response.raise_for_status()
        print("✅ Initial connection successful")
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        return False
    
    for test in tests:
        try:
            print(f"🧪 {test['name']}... ", end="", flush=True)
            
            response = session.get(f"{host}{test['endpoint']}")
            
            if response.status_code == 200:
                data = response.json()
                item_count = len(data.get('items', []))
                print(f"✅ OK ({item_count} items)")
                results.append(('PASS', test['name'], f"{item_count} items found"))
            elif response.status_code == 404:
                print("⚠️  Not Found (may not be available on this system)")
                results.append(('WARN', test['name'], 'Endpoint not found'))
            else:
                print(f"❌ Failed (HTTP {response.status_code})")
                results.append(('FAIL', test['name'], f"HTTP {response.status_code}: {response.reason}"))
                
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Connection Failed")
            results.append(('FAIL', test['name'], f"Connection error: {str(e)}"))
        except requests.exceptions.Timeout as e:
            print(f"❌ Timeout")
            results.append(('FAIL', test['name'], f"Timeout: {str(e)}"))
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            results.append(('FAIL', test['name'], f"Error: {str(e)}"))
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    
    passed = sum(1 for result in results if result[0] == 'PASS')
    warned = sum(1 for result in results if result[0] == 'WARN')
    failed = sum(1 for result in results if result[0] == 'FAIL')
    
    print(f"✅ Passed: {passed}")
    print(f"⚠️  Warnings: {warned}")
    print(f"❌ Failed: {failed}")
    
    if failed > 0:
        print("\n❌ Some tests failed. Details:")
        for status, name, details in results:
            if status == 'FAIL':
                print(f"   • {name}: {details}")
    
    if warned > 0:
        print("\n⚠️  Some endpoints were not found:")
        for status, name, details in results:
            if status == 'WARN':
                print(f"   • {name}: {details}")
    
    # System information
    try:
        print("\n" + "=" * 60)
        print("ℹ️  System Information")
        print("=" * 60)
        
        response = session.get(f"{host}/mgmt/tm/sys/version")
        if response.status_code == 200:
            version_info = response.json()
            entries = version_info.get('entries', {})
            for key, value in entries.items():
                if 'Product' in value.get('nestedStats', {}).get('entries', {}):
                    product = value['nestedStats']['entries']['Product']['description']
                    version = value['nestedStats']['entries']['Version']['description']
                    print(f"📦 Product: {product}")
                    print(f"🔢 Version: {version}")
                    break
        
    except Exception as e:
        print(f"Could not retrieve system information: {e}")
    
    # Certificate count
    try:
        response = session.get(f"{host}/mgmt/tm/sys/file/ssl-cert")
        if response.status_code == 200:
            cert_data = response.json()
            cert_count = len(cert_data.get('items', []))
            print(f"🔒 Total SSL Certificates: {cert_count}")
            
            # Count expired certificates
            now = datetime.now()
            expired_count = 0
            for cert in cert_data.get('items', []):
                try:
                    exp_date = datetime.fromtimestamp(cert.get('expirationDate', 0))
                    if exp_date < now:
                        expired_count += 1
                except:
                    pass
            
            print(f"⚠️  Expired Certificates: {expired_count}")
        
    except Exception as e:
        print(f"Could not retrieve certificate information: {e}")
    
    print("\n" + "=" * 60)
    
    if failed == 0:
        print("🎉 All critical tests passed! You can proceed with the certificate cleanup script.")
        return True
    else:
        print("❌ Some critical tests failed. Please resolve the issues before running the cleanup script.")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Test F5 BIG-IP connectivity and permissions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_connection.py --host 192.168.1.100 --username admin
  python test_connection.py --host mybigip.local --username admin --password mypass
        """
    )
    
    parser.add_argument('--host', required=True, help='F5 BIG-IP hostname or IP address')
    parser.add_argument('--username', required=True, help='F5 username')
    parser.add_argument('--password', help='F5 password (will prompt if not provided)')
    
    args = parser.parse_args()
    
    # Get password if not provided
    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    
    try:
        success = test_f5_connection(args.host, args.username, args.password)
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n❌ Test cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 