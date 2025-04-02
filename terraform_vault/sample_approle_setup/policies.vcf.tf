resource "vault_policy" "pki_vcm_revoke" {
  name   = "${var.pki_policy_preamble}_revoke"
  policy = <<EOT

  # Allow revoking certificates
  path "${var.pki_path}/revoke" {
    capabilities = ["create", "update"]
  }

  EOT
}

resource "vault_policy" "pki_vcm_create" {
  name   = "${var.pki_policy_preamble}_create"
  policy = <<EOT

  # Allow issuing certificates using predefined roles
  path "${var.pki_path}/issue/*" {
    capabilities = ["create", "update"]
  }

  # Allow signing CSRs (Certificate Signing Requests)
  path "${var.pki_path}/sign/*" {
    capabilities = ["create", "update"]
  }

  EOT
}

resource "vault_policy" "pki_vcm_read" {
  name   = "${var.pki_policy_preamble}_read"
  policy = <<EOT

  # Allow reading of issued certificates
  path "${var.pki_path}/certs*" {
    capabilities = ["read", "list"]
  }

  # Allow looking up issued certificates
  path "${var.pki_path}/cert/*" {
    capabilities = ["read"]
  }

  # Allow reading issuers but not modifying them
  path "${var.pki_path}/issuer/*" {
    capabilities = ["read", "list"]
  }

  # Allow reading of roles but not modifying them
  path "${var.pki_path}/roles*" {
    capabilities = [ "list", "read"]
  }

  # Allow reading current CRLs but not modifying them
  path "${var.pki_path}/crl" {
    capabilities = ["read"]
  }

  # Allow reading CA certificates but not modifying them
  path "${var.pki_path}/ca" {
    capabilities = ["read"]
  }

  # Prevent modifying PKI settings, roles, or the CA itself
  path "${var.pki_path}/config/*" {
    capabilities = []
  }

  EOT
}
