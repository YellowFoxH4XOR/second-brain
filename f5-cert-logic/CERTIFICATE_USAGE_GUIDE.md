# F5 BIG-IP Certificate Usage Locations

This document provides a comprehensive overview of all the places where SSL certificates can be used within F5 BIG-IP systems. Our cleanup script checks all these locations to ensure no certificate is deleted while still in use.

## 🔍 Comprehensive Certificate Usage Detection

### Core SSL/TLS Services

| Location | API Endpoint | Fields Checked | Purpose |
|----------|-------------|----------------|---------|
| **Client-SSL Profiles** | `/mgmt/tm/ltm/profile/client-ssl` | `certKeyChain[].cert` | Client-facing SSL termination |
| **Server-SSL Profiles** | `/mgmt/tm/ltm/profile/server-ssl` | `cert`, `key` | Backend SSL origination |

### Health Monitoring

| Location | API Endpoint | Fields Checked | Purpose |
|----------|-------------|----------------|---------|
| **LTM HTTPS Monitors** | `/mgmt/tm/ltm/monitor/https` | `cert` | Health check SSL authentication |
| **GTM HTTPS Monitors** | `/mgmt/tm/gtm/monitor/https` | `cert` | Global traffic management health checks |

### Security & Validation

| Location | API Endpoint | Fields Checked | Purpose |
|----------|-------------|----------------|---------|
| **OCSP Responders** | `/mgmt/tm/sys/crypto/cert-validator/ocsp` | `trustedResponders` | Certificate revocation checking |

### Authentication & Access Management

| Location | API Endpoint | Fields Checked | Purpose |
|----------|-------------|----------------|---------|
| **APM Authentication** | `/mgmt/tm/apm/profile/authentication` | `cert`, `trustedCAs` | Client certificate authentication, trusted CA validation |
| **LDAP Servers** | `/mgmt/tm/auth/ldap` | `sslCaCertFile`, `sslClientCert` | Secure LDAP connections (LDAPS) |
| **RADIUS Servers** | `/mgmt/tm/auth/radius-server` | `server.sslCaCertFile` | Secure RADIUS authentication |

### System Services

| Location | API Endpoint | Fields Checked | Purpose |
|----------|-------------|----------------|---------|
| **Syslog Destinations** | `/mgmt/tm/sys/syslog` | `remotesyslog.cert` | Encrypted syslog transmission |

## 🔧 Certificate Usage Context

### **Client-SSL Profiles** 🌐
- **What**: Handle incoming SSL/TLS connections from clients
- **Certificate Role**: Server certificate presented to clients
- **Impact if Expired**: Clients receive certificate warnings, connection failures
- **Replacement Strategy**: Use default certificate temporarily, plan proper renewal

### **Server-SSL Profiles** 🔒
- **What**: Manage outgoing SSL/TLS connections to backend servers
- **Certificate Role**: Client certificate for mutual authentication
- **Impact if Expired**: Backend authentication failures, service disruption
- **Replacement Strategy**: Use default certificate, may cause backend auth issues

### **HTTPS Monitors** 🏥
- **What**: Health checks that validate backend service availability
- **Certificate Role**: Client certificate for authenticated health checks
- **Impact if Expired**: Health check failures, false negative pool member status
- **Replacement Strategy**: Monitor functionality continues with default certificate

### **OCSP Responders** ✅
- **What**: Online Certificate Status Protocol for revocation checking
- **Certificate Role**: Trusted CA certificates for validating OCSP responses
- **Impact if Expired**: OCSP validation failures, potential security warnings
- **Replacement Strategy**: Default certificate maintains basic functionality

### **APM Authentication Profiles** 🛡️
Based on the [F5 Community documentation](https://community.f5.com/kb/technicalarticles/migrating-f5-big-ip-apm-from-legacy-nac-service-to-compliance-retrieval-service/309398), these are crucial for:
- **What**: Certificate-based user authentication via Access Policy Manager
- **Certificate Role**: Client certificates for user authentication, trusted CAs for validation
- **Impact if Expired**: User authentication failures, access denied
- **Replacement Strategy**: Immediate attention required, affects user access

### **LDAP Servers** 📋
- **What**: Secure LDAP (LDAPS) connections for user directory authentication
- **Certificate Role**: CA certificates for validating LDAP server identity
- **Impact if Expired**: LDAP authentication failures, user login issues
- **Replacement Strategy**: Default certificate maintains connection, may show warnings

### **RADIUS Servers** 🎯
- **What**: Secure RADIUS authentication for network access control
- **Certificate Role**: CA certificates for validating RADIUS server identity
- **Impact if Expired**: RADIUS authentication failures, network access issues
- **Replacement Strategy**: Service continues with default certificate

### **Syslog Destinations** 📝
- **What**: Encrypted log transmission to remote syslog servers
- **Certificate Role**: Client certificates for authenticated log transmission
- **Impact if Expired**: Log transmission failures, audit trail gaps
- **Replacement Strategy**: Logging continues with default certificate

## ⚠️ Critical Considerations

### **High-Priority Certificate Locations**
1. **APM Authentication** - Direct user access impact
2. **Client-SSL Profiles** - Customer-facing services
3. **LDAP/RADIUS Servers** - Authentication infrastructure
4. **Server-SSL Profiles** - Backend service integration

### **Medium-Priority Certificate Locations**
1. **HTTPS Monitors** - Health checking accuracy
2. **OCSP Responders** - Security validation
3. **Syslog Destinations** - Audit and compliance

### **Replacement Impact Assessment**

| Certificate Type | Default Cert Impact | User Visible | Service Impact |
|------------------|-------------------|--------------|----------------|
| Client-SSL | ⚠️ Certificate warnings | ✅ Yes | Medium |
| Server-SSL | 🔒 Backend auth issues | ❌ No | High |
| HTTPS Monitors | 📊 False health status | ❌ No | Low |
| APM Authentication | 🚫 Access denied | ✅ Yes | Critical |
| LDAP/RADIUS | ⚠️ Auth warnings | ❌ No | High |
| Syslog | 📝 Log warnings | ❌ No | Low |
| OCSP | ⚠️ Validation warnings | ❌ No | Medium |

## 🎯 Best Practices

### **Before Certificate Cleanup**
1. **Review Usage Report**: Carefully examine which services use each certificate
2. **Plan Maintenance Window**: Schedule cleanup during low-traffic periods
3. **Backup Configuration**: Save F5 configuration before making changes
4. **Test in Development**: Validate cleanup process in non-production environment

### **After Certificate Cleanup**
1. **Monitor Service Health**: Check all affected services post-cleanup
2. **Plan Certificate Renewal**: Schedule proper certificate installation
3. **Update Documentation**: Record which services were affected
4. **Review Alerts**: Address any certificate-related warnings

### **Long-term Certificate Management**
1. **Certificate Inventory**: Maintain comprehensive certificate tracking
2. **Renewal Automation**: Implement automated certificate renewal where possible
3. **Monitoring Setup**: Configure alerts for approaching certificate expiration
4. **Regular Audits**: Schedule periodic certificate usage audits

## 📚 Additional F5 Certificate Locations

### **Other Potential Certificate Usage** (Not Currently Scanned)
- **iRules**: Custom SSL logic may reference certificates
- **Device Certificates**: Management interface and device identity
- **CA Bundles**: System-wide trusted certificate authorities
- **Application Services**: AS3/DO declarative configurations
- **High Availability**: Sync and failover communications

### **Future Enhancements**
Our script focuses on the most common and API-accessible certificate usage locations. Future versions may include:
- iRule content scanning for certificate references
- CA bundle and trusted certificate authority checking
- Application Services (AS3/DO) configuration parsing
- Device certificate and HA communication certificate management

---

This comprehensive approach ensures that our certificate cleanup script provides maximum safety by checking all critical certificate usage locations before performing any deletions. 