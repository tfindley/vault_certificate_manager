resource "vault_policy" "pki_vcm_revoke" {
  name   = "intca_revoke"
  policy = <<EOT

  # Allow revoking certificates
  path "${vault_mount.pki_int.path}/revoke" {
    capabilities = ["create", "update"]
  }

  EOT
}

resource "vault_policy" "pki_vcm_create" {
  name   = "intca_create"
  policy = <<EOT

  # Allow issuing certificates using predefined roles
  path "${vault_mount.pki_int.path}/issue/*" {
    capabilities = ["create", "update"]
  }

  # Allow signing CSRs (Certificate Signing Requests)
  path "${vault_mount.pki_int.path}/sign/*" {
    capabilities = ["create", "update"]
  }

  EOT
}

resource "vault_policy" "pki_vcm_read" {
  name   = "intca_read"
  policy = <<EOT

  # Allow reading of issued certificates
  path "${vault_mount.pki_int.path}/certs*" {
    capabilities = ["read", "list"]
  }

  # Allow looking up issued certificates
  path "${vault_mount.pki_int.path}/cert/*" {
    capabilities = ["read"]
  }

  # Allow reading issuers but not modifying them
  path "${vault_mount.pki_int.path}/issuer/*" {
    capabilities = ["read", "list"]
  }

  # Allow reading of roles but not modifying them
  path "${vault_mount.pki_int.path}/roles*" {
    capabilities = [ "list", "read"]
  }

  # Allow reading current CRLs but not modifying them
  path "${vault_mount.pki_int.path}/crl" {
    capabilities = ["read"]
  }

  # Allow reading CA certificates but not modifying them
  path "${vault_mount.pki_int.path}/ca" {
    capabilities = ["read"]
  }

  # Prevent modifying PKI settings, roles, or the CA itself
  path "${vault_mount.pki_int.path}/config/*" {
    capabilities = []
  }

  EOT
}
