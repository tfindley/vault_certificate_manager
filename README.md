# Vault Certificate Manager

This Python script manages certificates issued by HashiCorp Vault. It validates, renews, deploys, and manages certificates based on a configuration file.

## Features

- Requests certificates from HashiCorp Vault.
- Stores certificates in a configurable directory.
- Deploys certificates to defined destinations with proper permissions.
- Restarts/reloads services when certificates are updated.

## Prerequisites

- Python 3.x
- HashiCorp Vault
- Required Python libraries: `requests`, `pyyaml`, `pyopenssl`

## Installation

1.  Install dependencies:

```sh
pip install -r requirements.txt
```

2.  Ensure Vault is accessible from the system.

## Configuration

Modify the `config.yaml` file:

- Set the Vault server, PKI role, and renewal threshold.
- Define where certificates should be stored and deployed.
- Specify services to restart upon renewal.

## Running the Script

To manually execute the script:

```sh
python3 main.py
```

### Automating with Cron

To run the script periodically, add a cron job:

```sh
crontab -e
```

Example cron job (runs every 6 hours):

```sh
0 */6 * * * /opt/vcm/main.py >/dev/null 2>&1
```

Example crontab (runs once a day at 04:05)

```sh
5 4 * * * /opt/vcm/main.py >/dev/null 2>&1
```

You can construct your own crontab easily using the [Crontab Generator](https://crontab-generator.org/)

## Security Considerations

- **Environment Variable First**: The script prioritizes the `VAULT_TOKEN` environment variable.
- **Token File Fallback**: If `VAULT_TOKEN` is not set, it reads from `token_file` (default: `/etc/vault-token`).
- **Restrict File Permissions**:

```sh
sudo chmod 600 /etc/vault-token
sudo chown root:root /etc/vault-token
```

## Logging

If `log_file` is set in `config.yaml`, logs are written there.

## License

MIT License
