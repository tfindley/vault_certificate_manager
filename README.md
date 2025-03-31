# Vault Certificate Manager (VCM)

This Python script manages certificates issued by HashiCorp Vault. It requests, renews, deploys, and manages certificates based on a configuration file.

## Features

- Requests certificates from HashiCorp Vault.
- Stores certificates in a defined directory.
- Deploys certificates to defined destinations with proper permissions.
- Restarts/reloads services after certificates are updated.
- Renews managed certificates.

## Prerequisites

- Python 3.x
- Python 3.x Virtual Environments module (venv)
- HashiCorp Vault
    - Vault's API 
- Required (additional) Python libraries:
    - `requests`
    - `pyyaml`
    - `pyopenssl`

## Prerequisites

We'll assume you already have python3 installed on your system, however you need to enusre you have python3 venv installed

- RHEL: `sudo yum install python3-venv`
- Debian: `sudo apt install python3-venv`

## Installation

As this is a raw python script it requires a little setup in order to get going.

0. Prerequisites

Ensure Vault is accessible from the system. - Ensure you can access the WebUI of your Vault server, and ensure suitable permissions on the Vault server. More information on this coming soon!

1. Create application directory and set permissions

I suggest placing the application in your `opt` directory, however this could just as easily run from your `root` home directory. For the sake of simplicity we'll use the first option for the examples. If you do change the installation path you'll need to modify the hashbang (`#!`) statement at line #1 in `main.py` so the script is executable.

```bash
sudo mkdir /opt/vcm
```

2. Get Files

**Option1:** Clone Respository with GIT

```bash
sudo git clone https://github.com/tfindley/vault_certificate_manager.git /opt/vcm
```

**Option2:** Download .zip and extract

```bash
wget https://github.com/tfindley/vault_certificate_manager/archive/refs/heads/main.zip
sudo unzip main.zip
mv vault_certificate_manager-main * /opt/vcm
rmdir vault_certificate_manager-main
```

3.  Install dependencies:

Now you've got all of the files down from git. we need to create our Python Virtual Environment and install dependencies.

Start with generating your venv inside of the vcm directory

```bash
cd /opt/vcm
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
```

Now you should have a fully build Python Virtual Environment which is ready to run the main.py script.

4. Edit the configuration file

See [below](#configuration) for details on the config.yml and its sections

5. Set permissions

The application should ideally run as root (or an equally privilaged user) as it needs to be able to manage service restarts. You could theoretically run this as another user however this is beyond the scope of this README.

```bash
sudo chown -R root:root /opt/vcm
sudo chmod 0700 /opt/vcm
sudo chmod 0700 /opt/vcm/main.py
sudo chmod 0600 /opt/config.yaml
```

6. Execute the application

```bash
/opt/vcm/main.py
```

7. Configure Crontab to run

See '[Automating with Cron](#automating-with-cron)' section below.

## Configuration

Modify the `config.yaml` file:

- Set the Vault server, PKI role, renewal threshold and access credentials.
- Define what certificates you want to generate
  - Define where certificates should be stored and deployed.
  - Specify services to restart upon renewal.

### Config

| Key                | Required | Overridable | Type   | Example Value                    | ENV Option        | Description |
| ------------------ | -------- | ----------- |------- | -------------------------------- | ----------------- | ----------- |
| `vault`            | True     | False       | string | `https://vault.example.com:8200` | `VAULT_ADDR`      | |
| `vault_ssl_verify` | False    | False       | string | `/etc/ssl/cert.pem`              |                   | |
| `pki`              | True     | True        | string | `pki`                            |                   | |
| `role`             | True     | True        | string | `pki_role`                       |                   | |
| `renew`            | True     | True        | string | `14d`                            |                   | |
| `cert_store`       | True     | False       | string | `/opt/vcm/certs`                 |                   | |
| `log_file`         | False    | False       | string | `/var/log/vert_manager.log`      |                   | |
| `token_file`       | False    | False       | string | `/etc/vault-token`               | `VAULT_TOKEN`     | |
| `vault_role_id`    | False    | False       | string | `your-role-id`                   | `VAULT_ROLE_ID`   | |
| `vault_secret_id`  | False    | False       | string | `your-role-secret-id`            | `VAULT_SECRET_ID` | |

### Certs

| Key                | Required | Overridable | Type   | Example Value                              | Description |
| ------------------ | -------- | ----------- |------- | ------------------------------------------ | ----------- |
| `name`             | True     | False       | string | `test.example.tld`                         | |
| `renew`            | True     | False       | string | `7d`                                       | |
| `ttl`              | True     | False       | string | `90d`                                      | |
| `pki`              | True     | False       | string | `anotherpki`                               | |
| `role`             | True     | False       | string | `anotherpki_role`                          | |
| `dns_sans`         | True     | False       | list   | `["name1.domain.tld", "name2.domain.tld"]` | |
| `ip_sans`          | True     | False       | list   | `["192.168.69.11", "192.168.69.101"]`      | |

#### Deploy

| Key                | Required | Overridable | Type   | Example Value                     | Description |
| ------------------ | -------- | ----------- |------- | --------------------------------- | ----------- |
| `source`           | True     | False       | string | `cert`                            | `cert`, `chain`, `fullchain`, `privkey` |
| `dest`             | True     | False       | string | `/opt/path/to/directory/cert.pem` | |
| `owner`            | True     | False       | string | `username`                        | |
| `group`            | True     | False       | string | `groupname`                       | |
| `mode`             | True     | False       | string | `0640`                            | |

#### Services

| Key                | Required | Overridable | Type   | Example Value   | Description |
| ------------------ | -------- | ----------- |------- | --------------- | ----------- |
| `name`             | True     | False       | string | `nginx.service` |             |
| `control`          | True     | False       | string | `reload`        | Choose from `reload` or `restart` depending on the service. |
| `order`            | True     | False       | int    | `1`             | |

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

## Good to knows

The python script will request certificates in the default format of the Vault PKI Role. If the role key type is set to 'any' there is no way to specify the certificate key type in the script. It will likely default to the defaults for the Python OpenSSL module (probably RSA2048), but I haven't tested this yet!

## Edge Cases

You are able to request a certificate for the same domain name more than once on the same host. In this instance, the python script would check for the existance of the CN directory and not request a new certificate. That cert would then be copied to any new destinations that you had specified. 

## Logging

If `log_file` is set in `config.yaml`, logs are written there.

## License

MIT License
