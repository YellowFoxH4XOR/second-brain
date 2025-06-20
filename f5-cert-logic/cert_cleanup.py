#!/usr/bin/env python3
#
# F5 BIG-IP Expired Certificate Cleanup Utility (API Edition)
#
# Description:
# This script connects to an F5 BIG-IP device via the iControl REST API
# to identify, classify, and process expired SSL certificates. It is designed
# to be run from a central management station with network access to the F5 devices.
#
# Logic Implemented from PRD v2.1:
# 1. Connects to the F5 REST API securely.
# 2. Fetches all non-system, user-installed SSL certificates.
# 3. For each certificate, it checks if the expiration date is in the past.
# 4. If a certificate is EXPIRED, it queries all relevant API endpoints to check
#    if the certificate is actively in use.
# 5. If EXPIRED and UNUSED:
#    - The public certificate text is backed up to a local timestamped folder.
#    - The certificate and its corresponding key are deleted from the BIG-IP.
# 6. If EXPIRED and IN-USE:
#    - The certificate's description is updated with a warning flag on the BIG-IP.
#    - No destructive action is taken.
# 7. A "dry-run" mode is supported to report on intended actions without making changes.
# 8. All actions and findings are logged to both the console and a timestamped log file.
#
# Author: Gemini AI
# Version: 2.1
# Date: June 20, 2025

import requests
import json
import os
import argparse
import logging
from datetime import datetime
from dateutil import parser as date_parser
import pytz
import getpass

# Suppress insecure request warnings for self-signed certificates.
# In a production environment with trusted CAs, this can be removed and `verify=True`.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
# F5 API endpoints to check for certificate usage as per PRD Section 4.
# Added APM profile check for more comprehensive coverage.
USAGE_CHECK_ENDPOINTS = [
    "/mgmt/tm/ltm/profile/client-ssl",
    "/mgmt/tm/ltm/profile/server-ssl",
    "/mgmt/tm/ltm/monitor/https",
    "/mgmt/tm/ltm/auth/ssl-cc-ldap",
    "/mgmt/tm/apm/profile/access",
]
# Base directory for storing backups as per PRD Section 6.
BACKUP_DIR_BASE = "f5_cert_backups"

# --- Logging Setup ---
def setup_logging(run_timestamp):
    """Sets up logging to a unique file and to the console."""
    log_filename = f'f5_cert_cleanup_{run_timestamp}.log'
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Log file created: {log_filename}")

# --- F5 API Interaction Class ---
class F5CertManager:
    """A class to manage all interactions with the F5 iControl REST API."""

    def __init__(self, host, user, password):
        """Initializes the API manager with connection details."""
        self.base_url = f"https://{host}"
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = False # Set to True if using trusted CAs
        self.session.headers.update({'Content-Type': 'application/json'})
        logging.info(f"F5CertManager initialized for host: {host}")

    def _get(self, endpoint):
        """Generic GET request handler with error handling."""
        try:
            response = self.session.get(f"{self.base_url}{endpoint}")
            # APM endpoint might not exist if the module is not provisioned.
            if response.status_code == 404:
                logging.warning(f"Endpoint {endpoint} not found (module may not be provisioned). Skipping check.")
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"API GET request to {endpoint} failed: {e}")
            return None

    def _patch(self, endpoint, payload):
        """Generic PATCH request handler for making updates."""
        try:
            response = self.session.patch(f"{self.base_url}{endpoint}", data=json.dumps(payload))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"API PATCH request to {endpoint} failed: {e}")
            return None

    def _delete(self, endpoint):
        """Generic DELETE request handler for removing objects."""
        try:
            response = self.session.delete(f"{self.base_url}{endpoint}")
            response.raise_for_status()
            # A successful DELETE often returns 204 No Content, which has no JSON body.
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"API DELETE request to {endpoint} failed: {e}")
            return False

    def check_connection(self):
        """FR-10: Verifies API connectivity by fetching system time."""
        logging.info(f"Checking API connection to {self.base_url}...")
        endpoint = "/mgmt/tm/sys/clock"
        response = self._get(endpoint)
        if response:
            logging.info("Successfully connected to F5 device.")
            return True
        logging.error("Failed to connect to F5 device. Please check host, username, and password.")
        return False

    def get_all_certificates(self):
        """FR-2: Retrieves a list of all non-system SSL certificates."""
        logging.info("Fetching all non-default SSL certificates...")
        endpoint = "/mgmt/tm/sys/file/ssl-cert"
        data = self._get(endpoint)
        if data and 'items' in data:
            # Filter out default system certs. Modify partitioning logic if needed.
            return [cert for cert in data['items'] if not cert.get('system', False)]
        return []
        
    def get_certificate_details(self, cert_self_link):
        """Gets full details of a specific cert, including its text for backup."""
        # The link from the list response is a full URI, so we just need the path part.
        endpoint = cert_self_link.split('localhost')[-1]
        return self._get(endpoint)

    def is_certificate_in_use(self, cert_name):
        """FR-4: Checks all relevant endpoints to see if a certificate is referenced."""
        logging.info(f"Certificate: {cert_name} - Checking usage across all relevant profiles and monitors...")
        for endpoint in USAGE_CHECK_ENDPOINTS:
            data = self._get(endpoint)
            if data and 'items' in data:
                # Convert the entire list of objects to a single JSON string for a robust search.
                # This finds the cert name regardless of the field it's in (e.g., 'cert', 'caFile').
                if cert_name in json.dumps(data['items']):
                    logging.warning(f"Certificate: {cert_name} - Found reference in configuration at endpoint: {endpoint}")
                    return True
        logging.info(f"Certificate: {cert_name} - No configuration usage found.")
        return False

    def flag_certificate(self, cert):
        """FR-7: Updates a certificate's description to flag it as expired but in use."""
        cert_name = cert['name']
        endpoint = f"/mgmt/tm/sys/file/ssl-cert/~{cert['partition']}~{cert_name}"
        payload = {"description": "FLAGGED: EXPIRED BUT IN USE - INVESTIGATE URGENTLY"}
        
        logging.warning(f"Certificate: {cert_name} - Flagging certificate by updating its description.")
        if self._patch(endpoint, payload):
             logging.info(f"Certificate: {cert_name} - Successfully flagged.")
        else:
             logging.error(f"Certificate: {cert_name} - Failed to flag.")

    def backup_and_delete_certificate(self, cert, backup_path):
        """FR-5 & FR-6: Backs up cert text, then deletes the cert and key from the BIG-IP."""
        cert_name = cert['name']
        # Derive the key name, which usually matches the cert name with a .key extension.
        key_name = cert.get('keyFileName', cert_name.replace('.crt', '.key'))
        partition = cert['partition']
        
        # 1. Backup public certificate text
        logging.info(f"Certificate: {cert_name} - Backing up certificate text before deletion...")
        cert_details = self.get_certificate_details(cert['selfLink'])
        if not cert_details or 'certificateText' not in cert_details:
             logging.error(f"Certificate: {cert_name} - Could not retrieve certificate text for backup. ABORTING DELETE.")
             return

        try:
            backup_file_path = os.path.join(backup_path, cert_name)
            with open(backup_file_path, 'w') as f:
                f.write(cert_details['certificateText'])
            logging.info(f"Certificate: {cert_name} - Backup of public cert successful to {backup_file_path}")
        except IOError as e:
            logging.error(f"Certificate: {cert_name} - Failed to write backup file: {e}. ABORTING DELETE.")
            return
            
        # 2. Delete Certificate Object
        cert_endpoint = f"/mgmt/tm/sys/file/ssl-cert/~{partition}~{cert_name}"
        logging.info(f"Certificate: {cert_name} - Deleting certificate object via API.")
        if self._delete(cert_endpoint):
            logging.info(f"Certificate: {cert_name} - Successfully deleted.")
        else:
            logging.error(f"Certificate: {cert_name} - Failed to delete. The corresponding key will not be deleted to be safe.")
            return

        # 3. Delete Key Object
        key_endpoint = f"/mgmt/tm/sys/file/ssl-key/~{partition}~{key_name}"
        logging.info(f"Key: {key_name} - Deleting corresponding key object via API.")
        if self._delete(key_endpoint):
            logging.info(f"Key: {key_name} - Successfully deleted.")
        else:
            logging.error(f"Key: {key_name} - Failed to delete. This may leave an orphaned key.")


# --- Main Execution Logic ---
def main():
    """Main function to parse arguments and drive the certificate cleanup process."""
    parser = argparse.ArgumentParser(
        description="F5 BIG-IP Expired Certificate Cleanup Utility (API Edition)",
        epilog="Example: python f5_cert_cleanup.py --host 10.10.1.1 --user myadmin --dry-run"
    )
    parser.add_argument("--host", required=True, help="F5 BIG-IP management IP or hostname.")
    parser.add_argument("--user", required=True, help="Username for F5 iControl REST API access.")
    parser.add_argument("--dry-run", action="store_true", help="Run in discovery mode. No changes will be made to the F5.")
    args = parser.parse_args()

    # Securely prompt for password instead of passing as an argument.
    password = getpass.getpass(f"Enter password for F5 user '{args.user}': ")

    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    setup_logging(run_timestamp)

    if args.dry_run:
        logging.info("--- Starting in DRY RUN mode. No changes will be made. ---")
    else:
        logging.info("--- Starting in EXECUTE mode. Changes WILL be made to the F5 device. ---")
        
    manager = F5CertManager(args.host, args.user, password)

    if not manager.check_connection():
        return # Exit if connection fails

    certificates = manager.get_all_certificates()
    if not certificates:
        logging.info("No non-default certificates were found to process.")
        return

    logging.info(f"Found {len(certificates)} non-default certificates to analyze.")
    
    expired_count = 0
    deleted_count = 0
    flagged_count = 0
    
    # Create the run-specific backup directory ahead of time if in execute mode.
    backup_path = os.path.join(BACKUP_DIR_BASE, run_timestamp)
    if not args.dry_run:
        os.makedirs(backup_path, exist_ok=True)
        logging.info(f"Created backup directory for this run: {backup_path}")

    utc_tz = pytz.utc
    now_utc = datetime.now(utc_tz)

    for cert in certificates:
        cert_name = cert['name']
        try:
            # FR-3: Parse the expiration string into a timezone-aware datetime object.
            expiration_str = cert.get('expirationString', '')
            expiration_date = date_parser.parse(expiration_str)
            
            # Make the parsed date timezone-aware (localize to UTC if no tzinfo).
            if expiration_date.tzinfo is None:
                expiration_date = utc_tz.localize(expiration_date)

        except (ValueError, KeyError) as e:
            logging.error(f"Certificate: {cert_name} - Could not parse expiration date '{expiration_str}'. Skipping. Error: {e}")
            continue

        # Compare current UTC time with the certificate's expiration time.
        if now_utc > expiration_date:
            expired_count += 1
            logging.warning(f"Certificate: {cert_name} - Status: EXPIRED on {expiration_date.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            
            is_in_use = manager.is_certificate_in_use(cert_name)

            if is_in_use:
                flagged_count += 1
                if not args.dry_run:
                    manager.flag_certificate(cert)
                else:
                    logging.info(f"DRY RUN: Certificate '{cert_name}' is IN-USE. Would have been flagged.")
            else:
                deleted_count += 1
                if not args.dry_run:
                    manager.backup_and_delete_certificate(cert, backup_path)
                else:
                    logging.info(f"DRY RUN: Certificate '{cert_name}' is UNUSED. Would have been backed up and deleted.")
        else:
            logging.info(f"Certificate: {cert_name} - Status: Valid until {expiration_date.strftime('%Y-%m-%d')}")
            
    logging.info("--- Cleanup Script Finished ---")
    logging.info(f"Summary: Processed {len(certificates)} certificates.")
    logging.info(f"Found {expired_count} expired certificates.")
    logging.info(f"Action - Flagged (Expired and In Use): {flagged_count}")
    logging.info(f"Action - Deleted (Expired and Unused): {deleted_count}")


if __name__ == "__main__":
    main()
