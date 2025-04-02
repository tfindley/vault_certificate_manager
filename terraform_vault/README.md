# Testing with Vault

## Prerequisites

Install Hashicorp Vault

Start Hashicorp Vault Server locally in Dev mode

```bash
vault server --dev
```

your CLI will now give you Vault Token. Copy that and paste it and export the two following ENVs, replacing the second one with the token you were given by the Vault Server Dev

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=
```

## Samples

I've included two samples 


### Applying changes to Vault using Terraform

## Init

Now cd into the `sample_approle_setup` directory.

Run:

```bash
terraform init
```

This will create some extra directories that are required to operate Hashicorp Terraform deployments.

## Plan

Now you're ready to go, you can run plan

```bash
terraform plan
```

Once run, review the changs that are going to be made


## Apply

Once you're happy with the changes, run:

```bash
terraform apply
```

Check these are all okay once again, then type `yes` and hit enter to apply the changes to Vault

## Result

Terraform will report back an AppRole ID (role_id).

Copy/paste the role_id into your config.yaml file


Terraform won't display the secret ID unless you prompt it. Use the following command to get the value:

```bash
terraform output -json secret_id
```

Copy/paste this into your config.yaml file

Now you have an approle created.