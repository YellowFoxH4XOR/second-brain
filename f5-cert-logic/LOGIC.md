# F5 Certificate Cleanup Logic

This document provides a comprehensive technical overview of the F5 Certificate Cleanup script, detailing its architecture, workflow, and core logic components. It is intended for developers and system administrators who need to understand, maintain, or extend the script.

## Table of Contents
1.  [**Overview**](#-overview)
2.  [**Data Models**](#-data-models)
3.  [**High-Level Workflow**](#-high-level-workflow)
4.  [**Certificate Discovery**](#-certificate-discovery-process)
5.  [**Usage Analysis**](#-usage-analysis-logic)
6.  [**Safety Checks**](#-safety-check-system)
7.  [**Certificate Dereferencing**](#-certificate-dereferencing-logic)
8.  [**Certificate Deletion**](#-certificate-deletion-process)
9.  [**Configuration Diff**](#-configuration-diff-generation)
10. [**Advanced Features**](#-advanced-features)
11. [**Execution Phases**](#-execution-phases)
12. [**Key Design Principles**](#-key-design-principles)

---

## 🎯 Overview

> The F5 Certificate Cleanup script is an automated tool designed to safely identify, dereference, and remove expired SSL certificates from F5 BIG-IP devices. It operates across all administrative partitions, handles complex object dependencies, and performs comprehensive safety checks to ensure zero service impact during cleanup operations. Its primary goal is to enhance security posture by automating the lifecycle management of SSL certificates.

---

## 📄 Data Models

The script uses several data classes to structure information during its execution.

### `CertificateInfo`
> Stores all relevant details about a discovered SSL certificate.

-   `name`: The short name of the certificate (e.g., `mycert.crt`).
-   `full_path`: The complete path, including partition (e.g., `/Common/mycert.crt`).
-   `expiration_date`: A `datetime` object representing the expiration date.
-   `days_until_expiry`: An integer indicating the number of days until expiration (negative if expired).
-   `is_expired`: A boolean flag, `True` if the certificate has expired.
-   `is_expiring_soon`: A boolean flag, `True` if the certificate is within the expiry threshold.
-   `subject`: The certificate's subject line.
-   `issuer`: The certificate's issuer.
-   `corresponding_key`: The name of the associated SSL key file (e.g., `mycert.key`).
-   `partition`: The administrative partition where the certificate resides.

### `CertificateUsage`
> Represents a single instance of a certificate being used by an F5 configuration object.

-   `object_type`: The type of F5 object using the certificate (e.g., `Client-SSL Profile`).
-   `object_name`: The name of the F5 object.
-   `object_path`: The full path of the F5 object.
-   `field_name`: The specific field where the certificate is referenced (e.g., `certKeyChain.cert`).
-   `partition`: The partition of the F5 object.

---

## 🔄 High-Level Workflow

> The script follows a structured, multi-phase process to ensure a safe and effective cleanup. It begins with discovery and analysis, proceeds to safety validation, executes the cleanup with user consent, and concludes with comprehensive reporting.

```mermaid
flowchart TD
    A[Start] --> B[Initialize F5 Connection]
    B --> C[Test Connection & TLS Compatibility]
    C --> D{Connection Success?}
    D -->|No| E[Exit with Error]
    D -->|Yes| F[Discover All Partitions]
    F --> G[Discover All Certificates]
    G --> H[Map Certificates to Keys]
    H --> I[Analyze Certificate Status]
    I --> J[Check Certificate Usage]
    J --> K[Generate HTML Report]
    K --> L{Report Only Mode?}
    L -->|Yes| M[Exit with Report]
    L -->|No| N[Pre-Cleanup Config Backup]
    N --> O[User Confirmation]
    O --> P{User Confirms?}
    P -->|No| Q[Exit]
    P -->|Yes| R[Execute Cleanup]
    R --> S[Post-Cleanup Config Backup]
    S --> T[Generate Configuration Diff]
    T --> U[Complete]
    
    style A fill:#e1f5fe
    style U fill:#e8f5e8
    style E fill:#ffebee
    style Q fill:#ffebee
```

---

## 🔍 Certificate Discovery Process

### Partition Discovery
> To ensure all certificates are found, the script first queries the F5 device to discover all administrative partitions. This allows it to scan beyond the default `Common` partition.

```mermaid
flowchart TD
    A[Start Partition Discovery] --> B[Query Auth Partition API]
    B --> C{API Success?}
    C -->|Yes| D[Parse Partition List]
    C -->|No| E[Fallback to Common Only]
    D --> F[Ensure Common Included]
    F --> G[Return Partition List]
    E --> G
    G --> H[Log Found Partitions]
    
    style A fill:#e1f5fe
    style G fill:#e8f5e8
    style E fill:#fff3e0
```

### Certificate and Key Discovery
> For each discovered partition, the script queries for all SSL certificates and keys. It parses certificate metadata, determines its expiration status, and intelligently maps each certificate to its corresponding private key based on common naming conventions.

```mermaid
flowchart TD
    A[Start Certificate Discovery] --> B[For Each Partition]
    B --> C[Query SSL Certificates]
    C --> D[Extract Certificate Details]
    D --> E[Parse Expiration Date]
    E --> F[Calculate Days Until Expiry]
    F --> G[Determine Status]
    G --> H[Query SSL Keys]
    H --> I[Map Certificates to Keys]
    I --> J{More Partitions?}
    J -->|Yes| B
    J -->|No| K[Return Certificate List]
    
    subgraph Certificate_Status
        L[Expired: Days Less Than 0]
        M[Expiring Soon: Days Less Than Threshold]
        N[Valid: Days Greater Than Threshold]
    end
    
    G --> Certificate_Status
    
    style A fill:#e1f5fe
    style K fill:#e8f5e8
```

---

## 🔬 Usage Analysis Logic

> This is a critical step where the script determines if a certificate is actively used by any F5 configuration object. The script can operate in two modes: a highly efficient bulk analysis mode or a fallback individual analysis mode.

```mermaid
flowchart TD
    A[Start Usage Analysis] --> B{Bulk Mode Enabled?}
    B -->|Yes| C[Bulk Analysis]
    B -->|No| D[Individual Analysis]
    
    C --> E[Fetch All Objects Per Partition]
    E --> F[Check All Certificates in Memory]
    
    D --> G[Check Each Certificate Individually]
    G --> H[Query Each Object Type]
    
    F --> I[Build Usage Map]
    H --> I
    
    I --> J[Check Object Types]
    
    subgraph Object_Types
        K[Client-SSL Profiles]
        L[Server-SSL Profiles]
        M[LTM HTTPS Monitors]
        N[GTM HTTPS Monitors]
        O[OCSP Responders]
        P[APM Authentication]
        Q[LDAP Servers]
        R[RADIUS Servers]
        S[Syslog Destinations]
    end
    
    J --> Object_Types
    Object_Types --> T[Return Usage Results]
    
    style A fill:#e1f5fe
    style T fill:#e8f5e8
    style C fill:#e3f2fd
    style D fill:#f3e5f5
```

### Partition-Aware API Queries
> All usage analysis queries are partition-aware, using the `$filter=partition eq {partition}` parameter to scope the search. This ensures accurate dependency checking in multi-tenant environments.

```mermaid
flowchart TD
    A[Certificate Usage Check] --> B[For Each Partition]
    B --> C[Build API Query with Partition Filter]
    C --> D[Execute Partition-Filtered API Call]
    D --> E[Parse Response Items]
    E --> F[Check Certificate Fields]
    F --> G{Certificate Found in Object?}
    G -->|Yes| H[Create CertificateUsage Record]
    G -->|No| I[Continue to Next Object]
    H --> J[Add to Usage List]
    I --> K{More Objects?}
    J --> K
    K -->|Yes| F
    K -->|No| L{More Partitions?}
    L -->|Yes| B
    L -->|No| M[Return Complete Usage Map]
    
    style A fill:#e1f5fe
    style M fill:#e8f5e8
    style H fill:#fff3e0
```

---

## 🛡️ Safety Check System

> Before any destructive operation, the script performs comprehensive safety checks to prevent service impact. It verifies the status of any Virtual Servers or GTM objects associated with the certificate being cleaned up.

```mermaid
flowchart TD
    A[Safety Check Required] --> B{SSL Profile Usage?}
    B -->|Yes| C[Virtual Server Status Check]
    B -->|No| D{GTM Monitor Usage?}
    
    C --> E[Find Virtual Servers Using Profile]
    E --> F[Check Each Virtual Server Status]
    F --> G{Any VS Active and Available?}
    G -->|Yes| H[BLOCK Operation]
    G -->|No| I[Allow Operation]
    
    D -->|Yes| J[GTM Object Status Check]
    D -->|No| I
    
    J --> K[Find GTM Pools Using Monitor]
    K --> L[Check GTM Object Status]
    L --> M{Any GTM Object Active?}
    M -->|Yes| H
    M -->|No| I
    
    H --> N[Log Safety Block Message]
    I --> O[Proceed with Operation]
    
    style A fill:#e1f5fe
    style H fill:#ffebee
    style I fill:#e8f5e8
    style N fill:#ffebee
    style O fill:#e8f5e8
```

### Virtual Server Status Logic
> The script determines if a Virtual Server is active by checking both its administrative `enabled` state and its operational `availabilityState` via the F5 stats endpoint.

```mermaid
flowchart TD
    A[Check Virtual Server Status] --> B[Find Virtual Servers Using SSL Profile]
    B --> C[For Each Virtual Server]
    C --> D[Construct API Path]
    D --> E[GET Virtual Server Config]
    E --> F[Check enabled and disabled flags]
    F --> G[GET Virtual Server Stats]
    G --> H[Parse Availability State]
    H --> I{Enabled and Available?}
    I -->|Yes| J[Mark as ACTIVE]
    I -->|No| K[Mark as INACTIVE]
    J --> L{More Virtual Servers?}
    K --> L
    L -->|Yes| C
    L -->|No| M[Return Status Summary]
    
    style A fill:#e1f5fe
    style M fill:#e8f5e8
    style J fill:#ffebee
    style K fill:#e8f5e8
```

---

## 🔄 Certificate Dereferencing Logic

> The dereferencing process safely replaces an expired certificate with an appropriate default certificate. It uses the correct partition-aware API path (`~Partition~ObjectName`) and modifies the relevant fields based on the object type.

```mermaid
flowchart TD
    A[Start Dereferencing] --> B[Get Default Certificate for Partition]
    B --> C[Construct F5 REST API Path]
    C --> D{Partition = Common?}
    D -->|Yes| E[Path: Common ObjectName]
    D -->|No| F[Path: Partition ObjectName]
    E --> G[Determine Object Type]
    F --> G
    
    G --> H{Object Type?}
    H -->|Client-SSL Profile| I[Update certKeyChain]
    H -->|Server-SSL Profile| J[Update cert and key fields]
    H -->|HTTPS Monitor| K[Update cert field]
    H -->|OCSP Responder| L[Update trustedResponders]
    H -->|APM Authentication| M[Update cert or trustedCAs]
    H -->|LDAP Server| N[Update sslCaCertFile and sslClientCert]
    H -->|RADIUS Server| O[Update server.sslCaCertFile]
    H -->|Syslog Destination| P[Update remotesyslog.cert]
    
    I --> Q[PATCH Request]
    J --> Q
    K --> Q
    L --> Q
    M --> Q
    N --> Q
    O --> Q
    P --> Q
    
    Q --> R{API Success?}
    R -->|Yes| S[Dereferencing Complete]
    R -->|No| T[Dereferencing Failed]
    
    style A fill:#e1f5fe
    style S fill:#e8f5e8
    style T fill:#ffebee
```

### Default Certificate Resolution
> The script intelligently resolves the correct default certificate to use. It first looks for a `default.crt` in the object's specific partition. If not found, it falls back to using the global `/Common/default.crt`.

```mermaid
flowchart TD
    A[Get Default Certificate] --> B[Check for Partition-Specific Default]
    B --> C[Query SSL Certs with Partition Filter]
    C --> D{Found default.crt in Partition?}
    D -->|Yes| E[Use Partition Default Certificate]
    D -->|No| F[Check Common Partition]
    F --> G[Query Common Partition SSL Certs]
    G --> H{Found default.crt in Common?}
    H -->|Yes| I[Use Common Default Certificate]
    H -->|No| J[Use Common Default - May Not Exist]
    
    E --> K[Return Certificate Paths]
    I --> K
    J --> K
    
    style A fill:#e1f5fe
    style K fill:#e8f5e8
    style J fill:#fff3e0
```

---

## 🗑️ Certificate Deletion Process

> After successful dereferencing, the certificate and its corresponding key are deleted. The script includes a final safety check to prevent accidental deletion of protected default certificates.

```mermaid
flowchart TD
    A[Start Deletion Process] --> B[Extract Partition from Path]
    B --> C{Full Path Format?}
    C -->|Yes| D[Parse Partition name format]
    C -->|No| E[Use provided partition or Common]
    
    D --> F[Construct API Path]
    E --> F
    F --> G{Partition = Common?}
    G -->|Yes| H[Path: Common name]
    G -->|No| I[Path: Partition name]
    
    H --> J[Safety Check: Is Default Certificate?]
    I --> J
    J --> K{Is Default/Protected?}
    K -->|Yes| L[REFUSE Deletion]
    K -->|No| M[Proceed with Deletion]
    
    M --> N[DELETE Certificate via API]
    N --> O{API Success?}
    O -->|Yes| P[Certificate Deleted]
    O -->|No| Q[Deletion Failed]
    
    L --> R[Return Protected Status]
    P --> S[Delete Corresponding Key]
    Q --> T[Return Error]
    
    S --> U[DELETE SSL Key via API]
    U --> V[Return Success Status]
    
    style A fill:#e1f5fe
    style P fill:#e8f5e8
    style L fill:#fff3e0
    style Q fill:#ffebee
    style T fill:#ffebee
    style V fill:#e8f5e8
```

---

## 📊 Configuration Diff Generation

> To provide a complete audit trail, the script captures the F5 running configuration both before and after the cleanup. It then generates a side-by-side HTML diff report to clearly visualize all changes.

```mermaid
flowchart TD
    A[Start Config Diff] --> B[Pre-Cleanup Snapshot]
    B --> C[Execute show running-config]
    C --> D[Capture SSL Profiles via REST API]
    D --> E[Capture Monitors via REST API]
    E --> F[Save Pre-Config with Timestamp]
    
    F --> G[CLEANUP OPERATIONS]
    G --> H[Post-Cleanup Snapshot]
    H --> I[Execute show running-config]
    I --> J[Capture SSL Profiles via REST API]
    J --> K[Capture Monitors via REST API]
    K --> L[Save Post-Config with Timestamp]
    
    L --> M[Generate Side-by-Side Diff]
    M --> N[Analyze Configuration Changes]
    N --> O[Create HTML Diff Report]
    
    subgraph Config_Methods
        P[Primary: tmsh show running-config]
        Q[Fallback: bash show running-config]
        R[Error Handling: Size validation]
    end
    
    C --> Config_Methods
    I --> Config_Methods
    
    style A fill:#e1f5fe
    style O fill:#e8f5e8
    style G fill:#fff3e0
```

### Configuration Diff Analysis
> The script analyzes the before and after snapshots to generate a structured report detailing every change, including modified profiles, updated monitors, and deleted certificates.

```mermaid
flowchart TD
    A[Analyze Configuration Changes] --> B[Compare SSL Profiles]
    B --> C[Compare Monitors]
    C --> D[Compare Certificates]
    D --> E[Generate Change Summary]
    
    B --> F[Profile-by-Profile Comparison]
    F --> G{Certificate Fields Changed?}
    G -->|Yes| H[Record Profile Change]
    G -->|No| I[No Change]
    
    C --> J[Monitor-by-Monitor Comparison]
    J --> K{Certificate Fields Changed?}
    K -->|Yes| L[Record Monitor Change]
    K -->|No| M[No Change]
    
    D --> N[Track Deleted Certificates]
    N --> O[Include Expiration Details]
    
    H --> E
    L --> E
    N --> E
    E --> P[Calculate Statistics]
    P --> Q[Return Change Report]
    
    style A fill:#e1f5fe
    style Q fill:#e8f5e8
```

---

## 🔧 Error Handling and Resilience

> The script is designed with resilience in mind. API call failures are handled gracefully. Non-critical errors are logged as warnings, allowing the script to continue, while critical failures will halt the process to prevent an inconsistent state.

```mermaid
flowchart TD
    A[Operation Start] --> B{API Call Required?}
    B -->|Yes| C[Make F5 REST API Call]
    B -->|No| G[Continue Operation]
    
    C --> D{API Success?}
    D -->|Yes| E[Process Response]
    D -->|No| F[Handle API Error]
    
    F --> H{Critical Error?}
    H -->|Yes| I[Log Error & Stop]
    H -->|No| J[Log Warning & Continue]
    
    E --> K{Response Valid?}
    K -->|Yes| G
    K -->|No| L[Log Data Warning]
    
    G --> M[Next Operation]
    J --> M
    L --> M
    
    I --> N[Return Error Status]
    M --> O{More Operations?}
    O -->|Yes| A
    O -->|No| P[Complete Successfully]
    
    style A fill:#e1f5fe
    style P fill:#e8f5e8
    style I fill:#ffebee
    style N fill:#ffebee
```

---

## 🎛️ Advanced Features

### Bulk Optimization Logic
> For performance, the bulk analysis mode significantly reduces API calls by fetching all objects of a given type from a partition at once, then checking for certificate usage in memory rather than making an API call for every certificate.

```mermaid
flowchart TD
    A[Bulk Mode Enabled] --> B[Calculate API Call Reduction]
    B --> C[Old Method: Certs times Partitions times Objects]
    C --> D[New Method: Partitions times Objects]
    D --> E[Performance Improvement Calculation]
    E --> F[Fetch All Objects by Type per Partition]
    F --> G[Create Certificate Path Set]
    G --> H[Check All Certificates in Memory]
    H --> I[Build Complete Usage Map]
    I --> J[Return Optimized Results]
    
    style A fill:#e1f5fe
    style J fill:#e8f5e8
    style E fill:#e3f2fd
```

### Multi-Partition Architecture
> The script is architected from the ground up to support multi-partition F5 environments, ensuring that all operations are correctly scoped and that object paths are constructed properly for non-Common partitions.

```mermaid
flowchart TD
    A[Multi-Partition Support] --> B[Discover All Partitions]
    B --> C[For Each Partition]
    C --> D[Partition-Filtered API Queries]
    D --> E[Proper F5 Path Construction]
    E --> F[Partition-ObjectName Format]
    F --> G[Cross-Partition Usage Analysis]
    G --> H[Partition-Specific Default Certificates]
    H --> I[Maintain Partition Isolation]
    I --> J{More Partitions?}
    J -->|Yes| C
    J -->|No| K[Complete Multi-Partition Operation]
    
    style A fill:#e1f5fe
    style K fill:#e8f5e8
    style F fill:#fff3e0
```

---

## 🚦 Execution Phases

The script operates in four distinct phases:

### Phase 1: Discovery and Analysis
> **Goal**: To build a complete picture of the certificate landscape without making any changes.
1.  **Connection Establishment**: TLS negotiation and authentication.
2.  **Partition Discovery**: Enumerate all administrative partitions.
3.  **Certificate Discovery**: Find all SSL certificates and keys.
4.  **Usage Analysis**: Perform comprehensive dependency checking.
5.  **Report Generation**: Create a detailed HTML analysis report.

### Phase 2: Safety Validation
> **Goal**: To ensure that the proposed cleanup is safe to execute.
1.  **Virtual Server Checks**: Verify no active services will be impacted.
2.  **GTM Object Checks**: Ensure traffic management continuity.
3.  **Default Certificate Validation**: Confirm replacement certificates exist.
4.  **User Confirmation**: Require interactive approval before making changes.

### Phase 3: Cleanup Execution
> **Goal**: To perform the certificate cleanup operations.
1.  **Pre-Cleanup Backup**: Save configuration snapshots and certificate data.
2.  **Unused Certificate Deletion**: Directly remove unused expired certificates.
3.  **Certificate Dereferencing**: Replace expired certificates in F5 objects.
4.  **Used Certificate Deletion**: Remove the now-unused certificates.
5.  **Post-Cleanup Verification**: Take a final configuration snapshot.

### Phase 4: Reporting and Audit
> **Goal**: To provide a complete and transparent audit trail of all actions taken.
1.  **Configuration Diff Generation**: Create a side-by-side before/after comparison.
2.  **Change Analysis**: Generate a structured breakdown of all modifications.
3.  **Audit Trail Creation**: Log all actions to the console and report files.
4.  **Success Metrics**: Output final statistics on completion.

---

## 💡 Key Design Principles

1.  **Safety First**: The script prioritizes preventing service impact above all else through its safety checks, user confirmation prompts, and detailed pre-action reporting.
2.  **Partition Awareness**: It correctly handles F5's partition-based architecture, ensuring accurate discovery and modification of objects in multi-tenant environments.
3.  **Comprehensive Coverage**: It scans a wide range of F5 object types that can reference certificates, including LTM, GTM, and optional modules like APM.
4.  **Performance Optimization**: Bulk API operations and intelligent caching are used to minimize API calls and reduce runtime on large F5 systems.
5.  **Detailed Auditing**: The script provides a complete audit trail through configuration backups, visual diff reports, and structured logs, ensuring full transparency.

This logic documentation provides the complete technical foundation for understanding how the F5 Certificate Cleanup script operates safely and efficiently across complex F5 environments. 