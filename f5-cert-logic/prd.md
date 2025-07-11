# Certificate Cleanup on F5 BIG-IP v17 Using Python and iControl REST

This guide walks through identifying, detaching, and removing **expired SSL certificates and their corresponding SSL keys** across **all administrative partitions** on an F5 BIG-IP (v17) device using the iControl REST API and Python. The procedure covers both LTM and GTM contexts and is designed to avoid service interruptions.

---

## Multi-Partition Support

The script automatically discovers and processes certificates across **all administrative partitions** on the F5 BIG-IP device:

- **Partition Discovery**: Uses `/mgmt/tm/auth/partition` to enumerate all partitions
- **Cross-Partition Certificate Discovery**: Finds certificates in all partitions using partition filtering
- **Cross-Partition Usage Checking**: Searches for certificate references across all partitions
- **Partition-Aware Default Replacement**: Uses partition-specific default certificates when available, falling back to `/Common/default.crt`

### Partition Support Benefits:
- **Complete Coverage**: No certificates are missed regardless of partition location
- **Isolated Operations**: Partition-specific configurations are properly handled
- **Smart Defaults**: Uses appropriate default certificates for each partition
- **Comprehensive Reporting**: Shows partition information for all certificates and usage



---

## 1. Identify Expired Certificates

1. **List all certificates**
   * Endpoint: `GET /mgmt/tm/sys/file/ssl-cert`
   * Each certificate object includes an `expirationDate` (epoch timestamp).

2. **Filter expired certificates**
   * Parse the JSON response with Python and compare `expirationDate` to `datetime.now()`.
   * Any certificate whose `expirationDate ≤ now` is considered **expired**.

```python
import requests, datetime, urllib3, json
urllib3.disable_warnings()

BIGIP = "https://BIGIP"
creds = ("user", "pass")

resp = requests.get(f"{BIGIP}/mgmt/tm/sys/file/ssl-cert", auth=creds, verify=False)
resp.raise_for_status()

expired = []
for cert in resp.json()["items"]:
    exp = datetime.datetime.fromtimestamp(cert["expirationDate"])
    if exp <= datetime.datetime.now():
        expired.append(cert["name"])

print("Expired certs:", json.dumps(expired, indent=2))
```

> ℹ️  The iControl REST object `tm:sys:file:ssl-cert` exposes `expirationDate` ([docs](https://clouddocs.f5.com)).

---

## 2. Check Certificate Usage in Configuration

For each **expired certificate**, determine whether it is referenced by any LTM or GTM object.

| Object Type | API Endpoint | Field(s) to Inspect |
|-------------|-------------|----------------------|
| **Client-SSL profile** | `GET /mgmt/tm/ltm/profile/client-ssl` | `certKeyChain[].cert` |
| **Server-SSL profile** | `GET /mgmt/tm/ltm/profile/server-ssl` | `cert`, `key` |
| **LTM HTTPS monitor** | `GET /mgmt/tm/ltm/monitor/https` | `cert` |
| **GTM HTTPS monitor** | `GET /mgmt/tm/gtm/monitor/https` | `cert` |
| **OCSP responder** | `GET /mgmt/tm/sys/crypto/cert-validator/ocsp` | `trustedResponders` |
| **APM authentication** | `GET /mgmt/tm/apm/profile/authentication` | `cert`, `trustedCAs` |
| **LDAP servers** | `GET /mgmt/tm/auth/ldap` | `sslCaCertFile`, `sslClientCert` |
| **RADIUS servers** | `GET /mgmt/tm/auth/radius-server` | `server.sslCaCertFile` |
| **Syslog destinations** | `GET /mgmt/tm/sys/syslog` | `remotesyslog.cert` |

> If the expired certificate's name (e.g. `/Common/expired.crt`) appears in any of these fields, the certificate is **in use**.

---

## 3. Safe Removal of Unused Expired Certificates

If an expired certificate is **not referenced** anywhere:

```bash
curl -sk -u user:pass \
  -X DELETE "https://BIGIP/mgmt/tm/sys/file/ssl-cert/{certName}"
```

Replace `{certName}` with the certificate's object name (e.g. `~Common~expired.crt`). Deletion is immediate.

> **Recommended staged deletion**  
> To add an extra safety-net, first **disable** the certificate object via iControl REST, wait one monitoring cycle, then delete:
>
> ```bash
> # Quarantine the cert (sets enabled=false)
> curl -sk -u user:pass \
>   -X PATCH \
>   -H "Content-Type: application/json" \
>   -d '{"enabled":false}' \
>   "https://BIGIP/mgmt/tm/sys/file/ssl-cert/{certName}"
>
> # — wait 5-10 minutes, watch /var/log/ltm for SSL alerts —
>
> # Permanently remove the cert
> curl -sk -u user:pass \
>   -X DELETE "https://BIGIP/mgmt/tm/sys/file/ssl-cert/{certName}"
> ```
>
> This two-step "quarantine then purge" approach mirrors the guidance in F5 KB [K55918586](https://my.f5.com/manage/s/article/K55918586).

---

## 4. Handling Expired Certificates *In Use*

For certificates that **are in use**, follow these steps **per certificate**:

1. **Verify service status** 
   * Check the health of related objects (virtual servers, pools) via stats endpoints, e.g. `GET /mgmt/tm/ltm/virtual/{vsName}/stats`.
   * Proceed during a maintenance window if services are active.

2. **Replace the certificate with the built-in default**

   **Example – Server-SSL profile**

```json
PATCH /mgmt/tm/ltm/profile/server-ssl/{profileName}
{
  "cert": "/Common/default.crt",
  "key":  "/Common/default.key"
}
```

   **Example – Client-SSL profile**

```json
PATCH /mgmt/tm/ltm/profile/client-ssl/{profileName}
{
  "certKeyChain": [
    {
      "name": "default",
      "cert": "/Common/default.crt",
      "key":  "/Common/default.key"
    }
  ]
}
```

3. **Update monitors** similarly, setting their `cert` (and `key`/`trustCA` if applicable) to `/Common/default.crt`.

4. **Validate functionality**
   * Test SSL handshakes or monitor health to ensure objects work with the default certificate.

5. **Delete the expired certificate** once it is no longer referenced (see Step&nbsp;3).

---

## 5. GTM Certificates

Apply the same logic to GTM-specific objects:

* **GTM SSL profiles** (if present): `GET /mgmt/tm/gtm/ssl-profile/...`
* **GTM HTTPS monitors**: `GET /mgmt/tm/gtm/monitor/https`

Replace expired certificates with `/Common/default.crt`, verify operation, then delete.

---

## 6. SSL Key Management

SSL keys are automatically discovered and mapped to their corresponding certificates using common naming patterns:

1. **Key Discovery**
   * Endpoint: `GET /mgmt/tm/sys/file/ssl-key`
   * Maps keys to certificates using naming conventions (`.crt` → `.key`, exact names, etc.)

2. **Automatic Key Deletion**
   * When a certificate is deleted, its corresponding SSL key is automatically deleted
   * Prevents orphaned private keys from remaining on the system
   * Enhances security by removing unused cryptographic material

```bash
# Keys are deleted automatically with certificates
curl -sk -u user:pass \
  -X DELETE "https://BIGIP/mgmt/tm/sys/file/ssl-key/{keyName}"
```

## 7. Final Verification

1. **Search for lingering references** to the deleted certificate names across all profiles, monitors, and iRules.
2. **Validate services**: Confirm that virtual servers, pools, and monitors are healthy.
3. **Verify key cleanup**: Confirm that corresponding SSL keys have been removed automatically.

---

### Sources & Further Reading

* F5 iControl REST API Reference – [SSL certificates](https://clouddocs.f5.com)
* F5 iControl REST API Reference – [Client-SSL profiles](https://clouddocs.f5.com)
* F5 iControl REST API Reference – [Server-SSL profiles](https://clouddocs.f5.com)
* F5 iControl REST API Reference – [LTM/GTM monitors](https://clouddocs.f5.com)
* Community examples – [loadbalancing.se](https://loadbalancing.se)

---

## 7. Batch Processing (Multiple Devices)

For enterprise environments with multiple F5 devices, the script supports batch processing via CSV input:

1. **Create devices.csv file**
   ```csv
   hostname,ip,username,password
   bigip-prod-01,192.168.1.100,admin,
   bigip-prod-02,192.168.1.101,admin,
   bigip-dev-01,192.168.1.200,testuser,testpass
   ```

2. **Execute batch processing**
   ```bash
   python f5_cert_cleanup.py --devices-csv devices.csv --username admin --report-only
   ```

3. **Review batch report**
   * Generates `f5_batch_cert_cleanup_report.html` with consolidated results
   * Shows per-device status, connection success/failure, and certificate summaries
   * Provides enterprise-wide certificate cleanup overview

4. **Batch cleanup execution**
   * Interactive confirmation per device with expired certificates
   * Options: `yes` (proceed), `no` (cancel), `skip` (skip this device)
   * Continues processing remaining devices after failures

**Batch Processing Benefits:**
- **Centralized Management**: Single command processes entire F5 infrastructure
- **Comprehensive Reporting**: Enterprise-wide certificate status overview
- **Resilient Operation**: Continues processing despite individual device failures
- **Flexible Authentication**: Supports device-specific or shared credentials
- **Risk Mitigation**: Per-device confirmation prevents mass accidental deletion

---

## 8. Automatic File Naming and Backup

The script provides intelligent file management:

### File Naming
- **Single Device Reports**: `f5_cert_cleanup_report_{device_ip}.html`
- **Batch Reports**: `f5_batch_cert_cleanup_report_{timestamp}.html`  
- **Certificate Backups**: `backup_{device_ip}.json`

### Automatic Backup
Before any certificate deletion, the script creates a comprehensive JSON backup containing:

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
  },
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
  ],
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

**Backup Benefits:**
- **Recovery**: Complete certificate and usage information for rollback
- **Audit Trail**: Timestamped record of all deletions
- **Documentation**: Reference for re-creating certificates if needed
- **Compliance**: Evidence of what was removed and when

---

By following these steps, you can safely remove expired and unused certificates from single or multiple BIG-IP devices without disrupting active traffic. 