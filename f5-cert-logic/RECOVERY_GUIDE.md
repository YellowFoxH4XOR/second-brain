# Certificate Recovery Guide

This guide explains how to use the JSON backup files created by the F5 certificate cleanup script to recover deleted certificates if needed.

## Overview

Before any certificate deletion, the script automatically creates a comprehensive JSON backup file named `backup_{device_ip}.json`. This file contains all the information needed to understand what was deleted and potentially recreate the configuration.

## Backup File Structure

The backup file contains three main sections:

### 1. Backup Metadata
```json
{
  "backup_metadata": {
    "timestamp": "2024-12-15T14:30:22.123456",
    "device_host": "192.168.1.100",
    "device_ip": "https://192.168.1.100",
    "script_version": "1.0",
    "backup_type": "certificate_cleanup",
    "total_certificates": 4,
    "total_used_certificates": 3
  }
}
```

### 2. Certificate Details
Complete information about each deleted certificate:
```json
{
  "certificates": [
    {
      "name": "expired_cert_1.crt",
      "full_path": "/Common/expired_cert_1.crt",
      "partition": "Common",
      "expiration_date": "2024-01-15T10:30:00",
      "days_until_expiry": -334,
      "is_expired": true,
      "subject": "CN=expired.example.com",
      "issuer": "CN=Example CA",
      "corresponding_key": "/Common/expired_cert_1.key"
    }
  ]
}
```

### 3. Usage Information
Where each certificate was used before deletion:
```json
{
  "usage_information": [
    {
      "certificate": {
        "name": "expired_cert_2.crt",
        "full_path": "/Common/expired_cert_2.crt",
        "partition": "Common"
      },
      "usage_locations": [
        {
          "object_type": "Client-SSL Profile",
          "object_name": "ssl_profile_1",
          "object_path": "/Common/ssl_profile_1", 
          "field_name": "certKeyChain.cert",
          "partition": "Common"
        }
      ]
    }
  ]
}
```

## Recovery Scenarios

### 1. Understanding What Was Deleted

To review what certificates were removed:

```bash
# View the backup file
cat backup_192_168_1_100.json | jq '.backup_metadata'

# List all deleted certificates
cat backup_192_168_1_100.json | jq '.certificates[].name'

# Show certificates that were in use
cat backup_192_168_1_100.json | jq '.usage_information[].certificate.name'
```

### 2. Identifying Previous Usage

To see where certificates were used:

```bash
# Show all usage locations for a specific certificate
cat backup_192_168_1_100.json | jq '.usage_information[] | select(.certificate.name == "expired_cert_2.crt")'

# List all F5 objects that were affected
cat backup_192_168_1_100.json | jq '.usage_information[].usage_locations[].object_name'
```

### 3. Manual Certificate Recreation

If you need to restore service with a new certificate:

#### Step 1: Install New Certificate
```bash
# Upload new certificate file to F5
curl -sku admin:password https://192.168.1.100/mgmt/tm/sys/file/ssl-cert \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{
    "name": "new_cert.crt",
    "partition": "Common", 
    "sourcePath": "file:///path/to/new_cert.crt"
  }'
```

#### Step 2: Update F5 Objects
Use the backup file to identify which objects need updating:

```bash
# Example: Update Client-SSL Profile
curl -sku admin:password https://192.168.1.100/mgmt/tm/ltm/profile/client-ssl/~Common~ssl_profile_1 \
  -H "Content-Type: application/json" \
  -X PATCH \
  -d '{
    "certKeyChain": [
      {
        "name": "default",
        "cert": "/Common/new_cert.crt",
        "key": "/Common/new_cert.key"
      }
    ]
  }'
```

### 4. Rollback to Default Configuration

If you need to revert to the default certificate configuration that the script applied:

```bash
# The script replaced expired certificates with /Common/default.crt
# Check current configuration to see if defaults are still in place
curl -sku admin:password https://192.168.1.100/mgmt/tm/ltm/profile/client-ssl/~Common~ssl_profile_1
```

## Recovery Best Practices

### 1. Immediate Actions (if needed)
- **Verify Service Impact**: Check if any services are affected by the certificate removal
- **Review Backup File**: Understand what was deleted and where it was used  
- **Plan Replacement**: Determine if new certificates are needed or if defaults are acceptable

### 2. Certificate Replacement Strategy
- **Obtain Valid Certificates**: Get new certificates from your CA for affected services
- **Use Backup Information**: Reference the backup file to understand subject names and usage
- **Update F5 Objects**: Use the usage information to update the correct F5 objects

### 3. Preventive Measures
- **Certificate Monitoring**: Implement certificate expiration monitoring
- **Regular Renewals**: Establish a certificate renewal process
- **Testing**: Test certificate changes in non-production environments first

## Automation Scripts

### Backup Analysis Script
```python
#!/usr/bin/env python3
import json
import sys
from datetime import datetime

def analyze_backup(backup_file):
    with open(backup_file, 'r') as f:
        data = json.load(f)
    
    print(f"Backup Analysis for {data['backup_metadata']['device_host']}")
    print(f"Backup Date: {data['backup_metadata']['timestamp']}")
    print(f"Total Certificates Deleted: {data['backup_metadata']['total_certificates']}")
    print(f"Certificates in Use: {data['backup_metadata']['total_used_certificates']}")
    
    print("\nDeleted Certificates:")
    for cert in data['certificates']:
        print(f"  - {cert['name']} (Partition: {cert['partition']})")
        print(f"    Subject: {cert['subject']}")
        print(f"    Expired: {cert['days_until_expiry']} days ago")
    
    print("\nF5 Objects Affected:")
    for usage in data['usage_information']:
        cert_name = usage['certificate']['name']
        print(f"\n  Certificate: {cert_name}")
        for location in usage['usage_locations']:
            print(f"    - {location['object_type']}: {location['object_name']}")
            print(f"      Field: {location['field_name']}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_backup.py backup_file.json")
        sys.exit(1)
    
    analyze_backup(sys.argv[1])
```

Usage:
```bash
python analyze_backup.py backup_192_168_1_100.json
```

## Support Information

### Backup File Location
- Single Device: `backup_{device_ip}.json` in the script directory
- Contains: Complete certificate and usage information
- Format: JSON with structured data for easy parsing

### Recovery Assistance
If you need help with certificate recovery:

1. **Review the backup file** to understand what was deleted
2. **Check F5 logs** for any SSL-related errors after cleanup
3. **Verify service status** for applications that used the deleted certificates
4. **Contact your certificate authority** for new certificates if needed

### Important Notes
- **Default Certificates**: The script replaces expired certificates with F5's default certificates
- **Service Continuity**: Services may show SSL warnings until proper certificates are installed
- **Backup Preservation**: Keep backup files for audit and compliance purposes
- **Recovery Time**: Plan for certificate procurement and installation time

---

**Remember**: The backup file is your complete record of what was changed. Always review it before taking any recovery actions. 