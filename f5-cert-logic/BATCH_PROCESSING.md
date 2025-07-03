# F5 BIG-IP Batch Certificate Cleanup Guide

This guide covers how to use the CSV batch processing feature to manage certificates across multiple F5 BIG-IP devices simultaneously.

## 🏢 When to Use Batch Processing

Batch processing is ideal for:
- **Enterprise environments** with multiple F5 devices
- **Scheduled maintenance** across F5 infrastructure
- **Compliance audits** requiring certificate inventory
- **Disaster recovery** certificate cleanup
- **Migration projects** involving multiple devices

## 📋 CSV File Format

Based on the [Python CSV handling documentation](https://www.pythontutorial.net/python-basics/python-read-csv-file/), our script supports flexible CSV formats.

### Basic CSV Structure

```csv
hostname,ip,username,password
bigip-prod-01,192.168.1.100,admin,
bigip-prod-02,192.168.1.101,admin,
bigip-dev-01,192.168.1.200,testuser,testpass
bigip-backup,192.168.1.150,,
```

### Supported Column Names

The script supports flexible column naming (case-insensitive):

| **Field** | **Supported Column Names** | **Required** | **Notes** |
|-----------|---------------------------|--------------|-----------|
| Hostname | `hostname`, `Hostname`, `HOSTNAME` | Optional* | Used for display purposes |
| IP Address | `ip`, `ip_address`, `IP`, `IP_Address` | Optional* | Device connection address |
| Username | `username`, `Username`, `USER` | Optional | Device-specific username |
| Password | `password`, `Password`, `PASS` | Optional | Leave empty for security |

*Either hostname or IP address must be provided

### Security Best Practices

#### ✅ Recommended (Secure)
```csv
hostname,ip,username,password
bigip-prod-01,192.168.1.100,admin,
bigip-prod-02,192.168.1.101,admin,
```
*Passwords provided via command line or interactive prompt*

#### ❌ Not Recommended (Insecure)
```csv
hostname,ip,username,password
bigip-prod-01,192.168.1.100,admin,supersecret123
bigip-prod-02,192.168.1.101,admin,anotherpwd456
```
*Passwords stored in plain text*

## 🚀 Batch Processing Workflow

### Step 1: Prepare Your CSV File

1. **Create `devices.csv`** using the example above
2. **Copy from template**:
   ```bash
   cp devices.csv.example devices.csv
   # Edit devices.csv with your device information
   ```

### Step 2: Test Connectivity (Recommended)

```bash
# Test each device individually first
python test_connection.py --host 192.168.1.100 --username admin
python test_connection.py --host 192.168.1.101 --username admin
```

### Step 3: Generate Batch Report

```bash
# Safe report-only mode first
python f5_cert_cleanup.py --devices-csv devices.csv --username admin --report-only
```

This generates `f5_batch_cert_cleanup_report.html` with:
- **Overall Summary**: Total devices, successful connections, expired certificates
- **Device-by-Device Results**: Individual device status and certificate details
- **Connection Failures**: Detailed error information for troubleshooting

### Step 4: Review Batch Report

Open `f5_batch_cert_cleanup_report.html` in your browser and verify:
- ✅ **Device Connectivity**: All expected devices connected successfully
- 📋 **Certificate Inventory**: Review expired certificates across all devices
- ⚠️ **Usage Analysis**: Check which certificates are safe to delete vs. in use
- ❌ **Connection Issues**: Resolve any failed device connections

### Step 5: Execute Batch Cleanup

```bash
# Execute cleanup with confirmation
python f5_cert_cleanup.py --devices-csv devices.csv --username admin
```

**Interactive Process:**
```
📟 Processing device 1/3: bigip-prod-01 (192.168.1.100)
⚠️  Found 3 expired certificate(s) on bigip-prod-01
❓ Proceed with cleanup on bigip-prod-01? (yes/no/skip): yes

📟 Processing device 2/3: bigip-prod-02 (192.168.1.101)  
⚠️  Found 1 expired certificate(s) on bigip-prod-02
❓ Proceed with cleanup on bigip-prod-02? (yes/no/skip): skip

📟 Processing device 3/3: bigip-dev-01 (192.168.1.200)
❌ Connection failed: [Connection error details]
```

**User Options:**
- **`yes`**: Proceed with cleanup on this device
- **`no`**: Cancel cleanup for this device (stops batch processing)
- **`skip`**: Skip this device, continue with remaining devices

## 📊 Batch Report Features

### Overall Summary Section
- 📈 **Statistics Grid**: Visual overview of all devices and certificates
- 🎯 **Key Metrics**: Total devices, successful connections, expired certificates
- ⏰ **Timestamp**: When the batch scan was performed

### Device-by-Device Results
- 🖥️ **Device Status**: Connection success/failure with clear indicators
- 📋 **Certificate Counts**: Total, expired, expiring, and safe-to-delete counts
- 📊 **Detailed Tables**: Individual certificate information with usage status
- ❌ **Error Details**: Specific error messages for failed connections

### Recommended Actions
- 🔧 **Prioritized Tasks**: Focus areas based on certificate risk and usage
- 📅 **Maintenance Planning**: Guidance for scheduling cleanup activities
- 🔄 **Coordination Notes**: Multi-device considerations

## 💡 Advanced Usage Tips

### Mixed Authentication
```csv
hostname,ip,username,password
bigip-prod-01,192.168.1.100,admin,
bigip-prod-02,192.168.1.101,admin,
bigip-dev-01,192.168.1.200,testuser,devpassword
special-device,192.168.1.99,operator,
```
- Devices without passwords use default credentials
- Devices with passwords use specific credentials
- Flexible authentication per device

### Partial Processing
```bash
# Process only specific expiry threshold
python f5_cert_cleanup.py --devices-csv devices.csv --username admin --expiry-days 7 --report-only

# Custom report filename
python f5_cert_cleanup.py --devices-csv devices.csv --username admin --batch-report-file weekly_cleanup.html
```

### Environment Variables
```bash
# Set default password via environment
export F5_DEFAULT_PASSWORD="your_secure_password"
python f5_cert_cleanup.py --devices-csv devices.csv --username admin --password "$F5_DEFAULT_PASSWORD"
```

## ⚠️ Production Considerations

### Pre-Production Testing
1. **Test in Development**: Run against dev/test F5 devices first
2. **Validate Connectivity**: Ensure all devices are reachable
3. **Review Credentials**: Verify authentication works for all devices
4. **Check Dependencies**: Ensure certificates aren't used by critical services

### Maintenance Windows
1. **Schedule Appropriately**: Run during low-traffic periods
2. **Coordinate Teams**: Inform application and network teams
3. **Backup Configuration**: Consider F5 configuration backups
4. **Monitor Services**: Watch for service disruptions during cleanup

### Risk Mitigation
1. **Staged Approach**: Process devices in small batches initially
2. **Skip Production**: Use `skip` option for critical production devices initially
3. **Rollback Plan**: Have certificate restoration procedure ready
4. **Communication**: Maintain clear communication with stakeholders

### Post-Cleanup Verification
1. **Service Health**: Verify all F5 services remain operational
2. **Certificate Warnings**: Address any SSL warnings in applications
3. **Monitoring Alerts**: Review monitoring systems for certificate-related alerts
4. **Documentation**: Update certificate inventory and renewal schedules

## 🐛 Troubleshooting

### Common CSV Issues
```
⚠️ Warning: Skipping row with missing hostname and IP: {'hostname': '', 'ip': '', ...}
```
**Solution**: Ensure each row has either hostname or IP address

### Connection Failures
```
❌ Connection failed: HTTPSConnectionPool(host='192.168.1.100', port=443)
```
**Possible Causes:**
- Network connectivity issues
- Incorrect IP address
- F5 management interface down
- Firewall blocking access

### Authentication Errors
```
❌ Connection failed: 401 Client Error: Unauthorized
```
**Possible Causes:**
- Incorrect username/password
- Account locked
- Insufficient privileges

### Memory Usage (Large Environments)
For environments with many devices (50+):
- Process in smaller batches
- Use `--report-only` mode for initial assessment
- Monitor system resources during processing

---

This batch processing capability transforms the F5 certificate cleanup script from a single-device tool into an enterprise-ready solution for managing certificates across your entire F5 infrastructure! 