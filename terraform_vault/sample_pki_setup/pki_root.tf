resource "vault_mount" "pki" {
  path        = "pki"
  type        = "pki"
  description = "This is an example PKI mount"

  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 315360000
}

resource "vault_pki_secret_backend_root_cert" "root_2023" {
   backend     = vault_mount.pki.path
   type        = "internal"
   common_name = "example.com"
   ttl         = 315360000
   issuer_name = "root-2023"
}

output "vault_pki_secret_backend_root_cert_root_2023" {
  value = vault_pki_secret_backend_root_cert.root_2023.certificate
}

resource "local_file" "root_2023_cert" {
  content  = vault_pki_secret_backend_root_cert.root_2023.certificate
  filename = "root_2023_ca.crt"
}

resource "vault_pki_secret_backend_issuer" "root_2023" {
  backend                        = vault_mount.pki.path
  issuer_ref                     = vault_pki_secret_backend_root_cert.root_2023.issuer_id
  issuer_name                    = vault_pki_secret_backend_root_cert.root_2023.issuer_name
  revocation_signature_algorithm = "SHA256WithRSA"
}

resource "vault_pki_secret_backend_role" "role" {
  backend          = vault_mount.pki.path
  name             = "2023-servers"
  ttl              = 86400
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = ["example.com", "my.domain"]
  allow_subdomains = true
  allow_any_name   = true
}

resource "vault_pki_secret_backend_config_urls" "config-urls" {
  backend                 = vault_mount.pki.path
  issuing_certificates    = ["http://localhost:8200/v1/pki/ca"]
  crl_distribution_points = ["http://localhost:8200/v1/pki/crl"]
}
