import os
import yaml
import logging
import requests
import subprocess
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

# CERT_STORE = os.path.join(SCRIPT_DIR, "certs")
CERT_STORE = config["config"].get("cert_store")
LOG_FILE = config["config"].get("log_file")
TOKEN_FILE = config["config"].get("token_file")
LOCAL_CA_CERT = os.path.join(SCRIPT_DIR, "vault_ca.pem")

# Handle SSL verification logic
if "vault_ssl_verify" in config["config"] and config["config"]["vault_ssl_verify"]:
    VAULT_SSL_VERIFY = config["config"]["vault_ssl_verify"]
elif os.path.exists(LOCAL_CA_CERT):
    VAULT_SSL_VERIFY = LOCAL_CA_CERT
else:
    VAULT_SSL_VERIFY = True

# Configure logging
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
        response = requests.post(url, headers=headers, json=data, verify=VAULT_SSL_VERIFY)
        response.raise_for_status()
        logging.info(f"Certificate requested for {cn}.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        return None
    return response.json()


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
    logging.info(f"Certificate saved for {cn}.")
    return paths


def deploy_certificate(cert_files, deploy_config):
    """Deploys certificate files only if they have changed."""
    if not cert_files:
        return
    for item in deploy_config:
        source = item["source"]
        dest_path = item["dest"]
        if source in cert_files and os.path.exists(cert_files[source]):
            if os.path.exists(dest_path):
                with open(cert_files[source], "r") as src, open(dest_path, "r") as dst:
                    if src.read() == dst.read():
                        continue
            os.system(f"cp {cert_files[source]} {dest_path}")
            os.system(f"chown {item['owner']}:{item['group']} {dest_path}")
            os.system(f"chmod {item['mode']} {dest_path}")
            logging.info(f"Deployed {source} to {dest_path}")


def restart_services(services):
    """Restarts or reloads services in specified order if a certificate was updated."""
    services.sort(key=lambda x: x.get("order", 0))
    for service in services:
        command = f"systemctl {service['control']} {service['name']}"
        subprocess.run(command, shell=True, check=False)
        logging.info(f"Executed: {command}")


def manage_certificates():
    """Handles certificate validation, renewal, deployment, and service restarts."""
    vault_addr = config["config"]["vault"]
    default_pki = config["config"]["pki"]
    default_role = config["config"]["role"]
    global_renew_days = int(config["config"].get("renew", "14d").strip("d"))
    vault_token = get_vault_token()
    # vault_token = os.getenv("VAULT_TOKEN")
    if not vault_token:
        logging.error("VAULT_TOKEN environment variable is not set.")
        return

    for cert in config["certs"]:
        cn = cert["name"]
        cert_path = os.path.join(CERT_STORE, cn, "cert.pem")
        expiry = get_cert_expiry(cert_path)
        renew_days = int(cert.get("renew", f"{global_renew_days}d").strip("d"))
        ttl = cert.get("ttl", "90d")
        pki = cert.get("pki", default_pki)
        role = cert.get("role", default_role)
        dns_sans = cert.get("dns_sans", [])
        ip_sans = cert.get("ip_sans", [])

        cert_files = None
        renewed = False
        if not expiry or expiry - timedelta(days=renew_days) <= datetime.now(timezone.utc):
            cert_data = request_certificate(vault_token, vault_addr, pki, role, cn, ttl, dns_sans, ip_sans)
            if cert_data:
                cert_files = save_certificate(cert_data, cn)
                renewed = True
        else:
            # Certificates weren't renewed, but check if files exist for deployment
            existing_cert_dir = os.path.join(CERT_STORE, cn)
            potential_paths = {
                "cert": os.path.join(existing_cert_dir, "cert.pem"),
                "chain": os.path.join(existing_cert_dir, "chain.pem"),
                "fullchain": os.path.join(existing_cert_dir, "fullchain.pem"),
                "privkey": os.path.join(existing_cert_dir, "privkey.pem"),
            }
            # Only set cert_files if all paths exist
            if all(os.path.exists(path) for path in potential_paths.values()):
                cert_files = potential_paths

        # Deploy certificates if deploy configuration is specified and cert_files exist
        if "deploy" in cert and cert_files:
            deploy_certificate(cert_files, cert["deploy"])

        # Restart services only if certificates were renewed
        if renewed and "service" in cert:
            restart_services(cert["service"])

if __name__ == "__main__":
    manage_certificates()