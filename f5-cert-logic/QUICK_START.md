# 🚀 Quick Start Guide

Get up and running with the F5 Certificate Cleanup Tool in 5 minutes!

## 1. Prerequisites Check ✅

Before starting, ensure you have:
- [ ] Python 3.7+ installed
- [ ] Network access to your F5 BIG-IP management interface
- [ ] F5 credentials with certificate management permissions
- [ ] Non-production F5 device for initial testing (recommended)

## 2. Installation 📦

```bash
# Clone/download the script files
git clone <repository> && cd f5-cert-logic

# Install Python dependencies
pip install -r requirements.txt

# Make scripts executable (Linux/Mac)
chmod +x f5_cert_cleanup.py test_connection.py
```

## 3. Test Connection 🔌

**ALWAYS test your connection first:**

```bash
# Test connectivity and permissions
python test_connection.py --host 192.168.1.100 --username admin
```

Expected output:
```
🔌 Testing connection to F5 BIG-IP: https://192.168.1.100
============================================================
🧪 Basic Authentication... ✅ OK (1 items)
🧪 Certificate Management Access... ✅ OK (25 items)
🧪 Client-SSL Profile Access... ✅ OK (15 items)
...
🎉 All critical tests passed! You can proceed with the certificate cleanup script.
```

If tests fail, check:
- Network connectivity
- Credentials
- F5 permissions

## 4. Generate Report (Dry Run) 📄

**ALWAYS generate a report first before making any changes:**

```bash
# Generate HTML report without making changes
python f5_cert_cleanup.py --host 192.168.1.100 --username admin --report-only
```

This creates `f5_cert_cleanup_report.html` - **Review this carefully!**

## 5. Review the Report 👀

Open the generated HTML report and verify:

- [ ] **Expired certificates** are correctly identified
- [ ] **Unused certificates** are safe to delete  
- [ ] **Used certificates** show expected usage locations (SSL profiles, monitors, APM, LDAP, etc.)
- [ ] **No critical authentication certificates** are marked for deletion
- [ ] **APM and authentication certificates** are handled with special care

## 6. Execute Cleanup 🧹

If the report looks good:

```bash
# Execute the cleanup (requires confirmation)
python f5_cert_cleanup.py --host 192.168.1.100 --username admin
```

The script will:
1. Show summary of what will be deleted
2. Ask for your confirmation (`yes/no`)
3. Safely clean up expired certificates
4. Replace used certificates with defaults

## 7. Verify Results ✅

After cleanup:
- [ ] Check F5 configuration is still working
- [ ] Verify services are healthy
- [ ] Review any SSL warnings (expected with default certificates)

---

## Quick Commands Reference

### Single Device
```bash
# Test connection only
python test_connection.py --host <F5_IP> --username <USER>

# Generate report only (safe)
python f5_cert_cleanup.py --host <F5_IP> --username <USER> --report-only

# Full cleanup with confirmation
python f5_cert_cleanup.py --host <F5_IP> --username <USER>
```

### Multiple Devices (CSV)
```bash
# Create devices.csv first, then:

# Generate batch report only (safe)
python f5_cert_cleanup.py --devices-csv devices.csv --username <USER> --report-only

# Full batch cleanup with confirmation
python f5_cert_cleanup.py --devices-csv devices.csv --username <USER>

# Custom expiry threshold (45 days)
python f5_cert_cleanup.py --devices-csv devices.csv --username <USER> --expiry-days 45
```

### CSV File Format
```csv
hostname,ip,username,password
bigip-01,192.168.1.100,admin,
bigip-02,192.168.1.101,admin,
```

## ⚠️ Safety Reminders

1. **Test in non-production first**
2. **Always review the HTML report**
3. **Backup F5 configuration if needed**
4. **Services using expired certs will show SSL warnings until renewed**

---

**Next Steps:** See [README.md](README.md) for detailed documentation and troubleshooting. 