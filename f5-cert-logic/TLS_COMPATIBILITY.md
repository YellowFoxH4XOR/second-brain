# F5 BIG-IP TLS Compatibility Guide

This document explains the TLS adapter functionality in the F5 certificate cleanup script, designed to handle connectivity across different F5 BIG-IP versions and configurations.

## Overview

F5 BIG-IP devices across different software versions may have varying TLS requirements, cipher support, and SSL configurations. The TLS adapter automatically handles these differences to ensure reliable API connectivity.

## TLS Version Strategies

### `auto` (Default - Recommended)
- **Behavior**: Attempts modern TLS (1.2/1.3) first, automatically falls back to legacy mode if connection fails
- **Use Case**: Default choice for most scenarios
- **Fallback**: Automatically tries `legacy` mode if initial connection fails
- **Example**: 
  ```bash
  python f5_cert_cleanup.py --host 192.168.1.100 --username admin --tls-version auto
  ```

### `legacy` 
- **Behavior**: Supports TLS 1.0 through TLS 1.2 for maximum compatibility
- **Use Case**: Older F5 devices (v11.x-v12.x) that may not support modern TLS
- **Security**: Less secure but necessary for older devices
- **Example**:
  ```bash
  python f5_cert_cleanup.py --host old-bigip.local --username admin --tls-version legacy
  ```

### `tlsv1_2`
- **Behavior**: Forces TLS 1.2 only
- **Use Case**: When you know the device supports TLS 1.2 and want to enforce it
- **Security**: Good security level, widely supported
- **Example**:
  ```bash
  python f5_cert_cleanup.py --host secure-bigip.local --username admin --tls-version tlsv1_2
  ```

### `tlsv1_3`
- **Behavior**: Forces TLS 1.3 only (falls back to 1.2 if not available)
- **Use Case**: Latest F5 devices with TLS 1.3 support
- **Security**: Highest security level
- **Example**:
  ```bash
  python f5_cert_cleanup.py --host new-bigip.local --username admin --tls-version tlsv1_3
  ```

### `tlsv1_1` / `tlsv1`
- **Behavior**: Forces specific older TLS versions
- **Use Case**: Very old F5 devices with limited TLS support
- **Security**: Not recommended unless absolutely necessary
- **Example**:
  ```bash
  python f5_cert_cleanup.py --host very-old-bigip.local --username admin --tls-version tlsv1_1
  ```

## F5 Version Compatibility Matrix

| F5 BIG-IP Version | Recommended TLS Strategy | Notes |
|-------------------|-------------------------|--------|
| **v17.x+** | `auto` | Latest versions with full TLS 1.3 support |
| **v15.x-v16.x** | `auto` | Modern versions, TLS 1.2/1.3 |
| **v13.x-v14.x** | `auto` or `tlsv1_2` | Good TLS 1.2 support |
| **v12.x** | `legacy` | May need older TLS versions |
| **v11.x** | `legacy` | Often requires TLS 1.0/1.1 support |
| **v10.x and older** | `legacy` | Very limited TLS support |

## Custom Cipher Suites

The `--ciphers` parameter allows you to specify custom cipher suites for special requirements:

### Examples:
```bash
# High security ciphers only
python f5_cert_cleanup.py --host bigip.local --username admin --ciphers "HIGH:!aNULL:!MD5"

# FIPS-compatible ciphers
python f5_cert_cleanup.py --host fips-bigip.local --username admin --ciphers "FIPS:!aNULL"

# Legacy compatibility ciphers
python f5_cert_cleanup.py --host old-bigip.local --username admin --ciphers "ALL:!aNULL:!eNULL"
```

### Common Cipher Suite Patterns:
- **`HIGH:!aNULL:!MD5`**: High-strength ciphers, no anonymous or MD5
- **`FIPS:!aNULL`**: FIPS 140-2 approved ciphers
- **`ALL:!aNULL:!eNULL`**: All ciphers except anonymous and null encryption
- **`ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS`**: Modern forward-secrecy ciphers

## Troubleshooting TLS Issues

### Connection Failures
1. **Start with `auto` mode** - Let the script try modern TLS with automatic fallback
2. **Try `legacy` mode** - If auto fails, older TLS versions might be required
3. **Check F5 version** - Verify the TLS capabilities of your specific F5 version
4. **Review logs** - Check F5 logs for SSL/TLS error messages

### Common Error Scenarios

#### SSL Handshake Failures
```
[SSL: CERTIFICATE_VERIFY_FAILED]
```
**Solution**: The script already disables certificate verification for self-signed certs

#### Protocol Version Errors
```
[SSL: WRONG_VERSION_NUMBER] or [SSL: UNSUPPORTED_PROTOCOL]
```
**Solution**: Try `--tls-version legacy` for older device compatibility

#### Cipher Suite Mismatches
```
[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]
```
**Solution**: Try custom cipher suites with `--ciphers` parameter

### Testing TLS Connectivity

Use the test script to verify TLS connectivity before running cleanup:

```bash
# Test with auto mode
python test_connection.py --host 192.168.1.100 --username admin --tls-version auto

# Test with legacy mode
python test_connection.py --host 192.168.1.100 --username admin --tls-version legacy

# Test with custom ciphers
python test_connection.py --host 192.168.1.100 --username admin --ciphers "HIGH:!aNULL"
```

## Batch Processing TLS Configuration

When processing multiple devices, all devices use the same TLS configuration:

```bash
# All devices use legacy TLS
python f5_cert_cleanup.py --devices-csv devices.csv --username admin --tls-version legacy

# All devices use auto mode with custom ciphers
python f5_cert_cleanup.py --devices-csv devices.csv --username admin --tls-version auto --ciphers "HIGH:!aNULL:!MD5"
```

For mixed environments with different TLS requirements, consider running separate batches or using the `auto` mode which provides intelligent fallback.

## Security Considerations

1. **Prefer Modern TLS**: Use `auto` or `tlsv1_2`/`tlsv1_3` when possible
2. **Legacy Mode Risks**: `legacy` mode enables older, less secure TLS versions
3. **Certificate Validation**: Script disables certificate verification due to common self-signed cert usage
4. **Network Security**: Always use secure networks for F5 management operations
5. **Credential Protection**: Never log or store credentials in scripts

## Advanced Configuration

### Environment-Specific Settings

For consistent TLS configuration across environments, consider environment variables:

```bash
export F5_TLS_VERSION=legacy
export F5_CIPHERS="HIGH:!aNULL:!MD5"
```

### Integration with Automation Tools

The TLS adapter can be imported and used in custom automation scripts:

```python
from f5_cert_cleanup import get_f5_compatible_session

# Create a session with specific TLS configuration
session = get_f5_compatible_session(
    tls_version='tlsv1_2',
    ciphers='HIGH:!aNULL:!MD5',
    max_retries=3
)
```

## References

- [F5 SSL/TLS Overview](https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-ssl-administration-11-6-0/13.html)
- [F5 DevCentral TLS Automation](https://github.com/f5devcentral/f5-tls-automation)
- [Python SSL/TLS Documentation](https://docs.python.org/3/library/ssl.html)
- [Requests SSL Configuration](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification) 