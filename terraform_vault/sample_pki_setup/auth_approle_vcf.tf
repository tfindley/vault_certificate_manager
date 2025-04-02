# 1. Enable AppRole auth method at a custom path (optional)
resource "vault_auth_backend" "approle" {
  type        = "approle"
  path        = "approle"
  description = "Application Roles"
}

# 2. Create the AppRole
resource "vault_approle_auth_backend_role" "vcm" {
  backend = vault_auth_backend.approle.path
  #   backend        = "approle"
  role_name      = "vcm_metrics"
  token_policies = ["intca_read", "intca_create", "intca_revoke"]

  # Optional hardening
  # secret_id_ttl          = "60m"
  token_ttl     = 600
  token_max_ttl = 7200
  # secret_id_num_uses     = 10
  token_num_uses = 10
}

# 3. Generate a Secret ID (one-time)
resource "vault_approle_auth_backend_role_secret_id" "vcm" {
  backend = vault_auth_backend.approle.path
  #   backend        = "approle"
  role_name = vault_approle_auth_backend_role.vcm.role_name
}

# 4. Output Role ID and Secret ID
output "role_id" {
  value = vault_approle_auth_backend_role.vcm.role_id
}

output "secret_id" {
  value     = vault_approle_auth_backend_role_secret_id.vcm.secret_id
  sensitive = true
}

# Note: this will still output secret_id as an obscured sensitive value.
# to retirieve this afterwards, run:
#
# terraform output -json secret_id
#
