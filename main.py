import os
import yaml
import logging
import requests
import subprocess
import json
from datetime import datetime, timedelta, timezone
from OpenSSL import crypto

# Load configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.yaml")

def load_config():
    """Loads the YAML configuration file."""
    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f)

config = load_config()

# Paths from config with defaults
CERT_STORE = config["config"].get("cert_store", os.path.join(SCRIPT_DIR, "certs"))
LOG_FILE = config["config"].get("log_file")
REPORT_FILE = config["config"].get("report_file")
TOKEN_FILE = config["config"].get("token_file", "/etc/vault-token")
LOCAL_CA_CERT = os.path.join(SCRIPT_DIR, "vault_ca.pem")
SYSTEM_CA_CERT = "/etc/ssl/certs/ca-certificates.crt"
VAULT_CA_CERT = LOCAL_CA_CERT if os.path.exists(LOCAL_CA_CERT) else SYSTEM_CA_CERT

# Configure logging if log_file is defined
if LOG_FILE:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

def get_vault_token():
    """Retrieve VAULT_TOKEN from environment or secure file."""
    token = os.getenv("VAULT_TOKEN")
    if not token and os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            token = f.read().strip()
    return token


def get_cert_expiry(cert_path):
    """Gets the expiration date of a certificate if it exists."""
    if not os.path.exists(cert_path):
        return None
    with open(cert_path, "r") as f:
        cert_data = f.read()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    return datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def restart_services(services):
    """Restarts or reloads services in specified order."""
    services.sort(key=lambda x: x.get("order", 0))
    for service in services:
        command = f"systemctl {service['control']} {service['name']}"
        subprocess.run(command, shell=True, check=False)
        if LOG_FILE:
            logging.info(f"Executed: {command}")


def generate_report(report_data):
    """Generates a JSON report with certificate status if REPORT_FILE is defined."""
    if REPORT_FILE:
        with open(REPORT_FILE, "w") as f:
            json.dump(report_data, f, indent=4)


def request_certificate(vault_token, vault_addr, pki, role, cn, ttl, dns_sans=None, ip_sans=None):
    """Requests a new certificate from HashiCorp Vault."""
    url = f"{vault_addr}/v1/{pki}/issue/{role}"
    headers = {"X-Vault-Token": vault_token}
    data = {"common_name": cn, "ttl": ttl}
    if dns_sans:
        data["alt_names"] = ",".join(dns_sans)
    if ip_sans:
        data["ip_sans"] = ",".join(ip_sans)
    try:
        response = requests.post(url, headers=headers, json=data, verify=VAULT_CA_CERT)
        response.raise_for_status()
        if LOG_FILE:
            logging.info(f"Certificate requested for {cn}.")
        return response.json()
    except requests.exceptions.RequestException as e:
        if LOG_FILE:
            logging.error(f"Request error: {e}")
        return None


def save_certificate(cert_data, cn):
    """Saves the retrieved certificate and keys in the correct location."""
    cert_dir = os.path.join(CERT_STORE, cn)
    os.makedirs(cert_dir, exist_ok=True)
    paths = {
        "cert": os.path.join(cert_dir, "cert.pem"),
        "chain": os.path.join(cert_dir, "chain.pem"),
        "fullchain": os.path.join(cert_dir, "fullchain.pem"),
        "privkey": os.path.join(cert_dir, "privkey.pem"),
    }
    
    # Write certificate data to files
    with open(paths["cert"], "w") as f:
        f.write(cert_data["data"]["certificate"])
    with open(paths["chain"], "w") as f:
        f.write("\n".join(cert_data["data"]["ca_chain"]))
    with open(paths["fullchain"], "w") as f:
        f.write(cert_data["data"]["certificate"] + "\n" + "\n".join(cert_data["data"]["ca_chain"]))
    with open(paths["privkey"], "w") as f:
        f.write(cert_data["data"]["private_key"])
    if LOG_FILE:
        logging.info(f"Certificate saved for {cn}.")
    return paths


def manage_certificates():
    """Handles certificate validation, renewal, deployment, and service restarts."""
    vault_addr = config["config"]["vault"]
    default_pki = config["config"]["pki"]
    default_role = config["config"]["role"]
    global_renew_days = int(config["config"].get("renew", "14d").strip("d"))
    vault_token = get_vault_token()
    if not vault_token:
        if LOG_FILE:
            logging.error("VAULT_TOKEN is not set or available.")
        return
    
    report_data = []

    for cert in config["certs"]:
        cn = cert["name"]
        cert_path = os.path.join(CERT_STORE, cn, "cert.pem")
        cert_files = None
        cert_data = None
        expiry = get_cert_expiry(cert_path)
        renew_days = int(cert.get("renew", f"{global_renew_days}d").strip("d"))
        ttl = cert.get("ttl", "90d")
        pki = cert.get("pki", default_pki)
        role = cert.get("role", default_role)
        dns_sans = cert.get("dns_sans", [])
        ip_sans = cert.get("ip_sans", [])
        
        if not expiry or expiry - timedelta(days=renew_days) <= datetime.now(timezone.utc):
            cert_data = request_certificate(vault_token, vault_addr, pki, role, cn, ttl, dns_sans, ip_sans)
            if cert_data:
                cert_files = save_certificate(cert_data, cn)
                expiry = get_cert_expiry(cert_path)
                if "service" in cert:
                    restart_services(cert["service"])
        
        destinations = [d["dest"] for d in cert.get("deploy", [])]
        report_data.append({
            "certificate": cn,
            "expiry_date": expiry.isoformat() if expiry else "Unknown",
            "services": [s["name"] for s in cert.get("service", [])],
            "destinations": destinations
        })

    generate_report(report_data)

if __name__ == "__main__":
    manage_certificates()

