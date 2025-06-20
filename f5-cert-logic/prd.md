Product Requirements Document: F5 BIG-IP Expired Certificate Cleanup Utility (API Edition)
Document Version

2.1

Status

Final

Author

Gemini AI

Date

June 20, 2025

Stakeholders

Network Operations, Security Engineering, IT Compliance, Automation Team

1. Introduction
Managing the lifecycle of SSL/TLS certificates on F5 BIG-IP devices is a critical operational task. The accumulation of expired certificates creates security risks, audit failures, and administrative clutter. Manually identifying, verifying, and cleaning up these certificates is time-consuming, prone to human error, and can lead to service disruptions if an in-use certificate is accidentally deleted.

This document outlines the requirements for an automated F5 BIG-IP Expired Certificate Cleanup Utility. This command-line tool will leverage the F5 iControl REST API to safely identify, classify, and process expired certificates, automating the entire cleanup workflow while prioritizing safety through comprehensive checks, backups, and detailed logging.

2. Goals and Objectives
Improve Security Posture: Systematically remove unused and expired certificates that could be potential attack vectors.

Enhance Operational Efficiency: Drastically reduce the manual effort and time required for certificate management.

Prevent Service Outages: Eliminate the risk of accidentally deleting an expired certificate that is still in use by an active configuration object.

Ensure Audit Compliance: Provide clear, auditable logs of all actions taken, demonstrating proper certificate lifecycle management.

Promote Modern Automation: Build a tool that aligns with Infrastructure-as-Code (IaC) principles and can be integrated into larger automation frameworks.

3. Scope
3.1. In-Scope
Securely connect to a target F5 BIG-IP device's iControl REST API over HTTPS.

Discover all non-default SSL certificates and their corresponding keys via API calls.

Analyze each certificate to determine if it is expired based on the current system date.

For each expired certificate, perform a comprehensive check by querying all relevant API endpoints to determine if it is actively referenced by any object.

Action Logic (via API):

If a certificate is expired and not in use, the utility shall back it up and then delete it from the BIG-IP.

If a certificate is expired but still in use, the utility shall "flag" the certificate by modifying its description on the BIG-IP and report it, taking no destructive action.

Create a detailed, timestamped log file of all findings and actions.

Provide a "Dry Run" mode that reports on what actions would be taken without making any actual changes to the system.

3.2. Out-of-Scope
A graphical user interface (GUI).

Automatic renewal or issuance of certificates.

Direct interaction with the BIG-IP via SSH/TMSH. The utility will be API-only.

Management of certificates on devices other than F5 BIG-IP.

4. API Endpoint Reference
The utility will use the following iControl REST API endpoints to perform its functions.

Function

HTTP Method

Endpoint

Discovery





List All Certificates

GET

/mgmt/tm/sys/file/ssl-cert

Get Certificate Details

GET

/mgmt/tm/sys/file/ssl-cert/~[partition]~[cert_name]

List All Keys

GET

/mgmt/tm/sys/file/ssl-key

Usage Verification





Check Client SSL Profiles

GET

/mgmt/tm/ltm/profile/client-ssl

Check Server SSL Profiles

GET

/mgmt/tm/ltm/profile/server-ssl

Check HTTPS Monitors

GET

/mgmt/tm/ltm/monitor/https

Check Auth Profiles

GET

/mgmt/tm/ltm/auth/ssl-cc-ldap

Check APM Policies

GET

/mgmt/tm/apm/profile/access

Actions





Flag Certificate

PATCH

/mgmt/tm/sys/file/ssl-cert/~[partition]~[cert_name]

Delete Certificate

DELETE

/mgmt/tm/sys/file/ssl-cert/~[partition]~[cert_name]

Delete Key

DELETE

/mgmt/tm/sys/file/ssl-key/~[partition]~[key_name]

5. Functional Requirements
ID

Requirement

Details

FR-1

Secure API Connectivity

The utility must connect to the target BIG-IP's REST API over HTTPS (port 443). It shall use Basic Authentication (user/password) or Token-Based Authentication. Credentials must not be stored in plain text.

FR-2

API-Based Discovery

The utility shall use the GET /mgmt/tm/sys/file/ssl-cert endpoint to enumerate all certificates and their properties.

FR-3

Expiration Analysis

The utility must accurately parse the expirationString field from the JSON response for each certificate and compare it against the current date to determine if it has expired.

FR-4

API-Based Usage Verification

For any expired certificate, the utility must query all endpoints listed in the "Usage Verification" table (Section 4) and parse the JSON responses to check for any references to the certificate's name.

FR-5

Certificate Backup

Before deleting a certificate, the utility must back it up. The API-based backup process is detailed in Section 7.

FR-6

API Deletion

If a certificate is confirmed to be expired AND unused, the utility shall issue DELETE requests to the appropriate ssl-cert and ssl-key endpoints.

FR-7

API Flagging

If a certificate is expired BUT in use, the utility shall issue a PATCH request to the certificate's endpoint with a JSON body to update its description: {"description": "FLAGGED: EXPIRED BUT IN USE - INVESTIGATE URGENTLY"}.

FR-8

Detailed Logging

The utility must generate a human-readable log file for each run, detailing all API calls made, findings, and actions taken.

FR-9

Execution Modes

The utility must support two execution modes: 
 • --dry-run: Reports all findings and intended actions without making DELETE or PATCH calls. 
 • --execute: Performs all backup, deletion, and flagging operations.

FR-10

API Pre-run Checks

The utility should perform a pre-run check to confirm API connectivity to the target device (e.g., by querying /mgmt/tm/sys/clock) and that the credentials provided result in a 200 OK response.

6. Backup Mechanism Details (API Method)
The API-based backup process is a critical safety net.

Backup Location: A local directory on the machine running the utility (e.g., ./f5_cert_backups/).

Run-Specific Subdirectory: A new subdirectory shall be created for each execution, named with a timestamp (e.g., ./f5_cert_backups/2025-06-20_07-57-00/).

File Backup Process: Before a certificate is deleted, the utility will:

Make a GET request to that specific certificate's endpoint (e.g., /mgmt/tm/sys/file/ssl-cert/~Common~my-cert.crt).

Extract the value of the certificateText field from the JSON response.

Save this content locally to a file with the original name (e.g., my-cert.crt) inside the run-specific backup directory.

Log the name of the corresponding key that will be deleted. Note: The private key content is not exposed via the REST API for security reasons. The backup consists of the public certificate and a record of the associated key's deletion.

7. Assumptions and Dependencies
The utility will be run from a machine with HTTPS network access to the F5 BIG-IP management interface.

The user account for the API has sufficient permissions (e.g., Administrator or a custom role with full access to LTM, SYS, and APM objects).

The target F5 BIG-IP device is running a version of TMOS that supports the iControl REST API (v11.5+).

The utility will be developed in a language with robust HTTP and JSON processing capabilities (e.g., Python, Go, PowerShell).