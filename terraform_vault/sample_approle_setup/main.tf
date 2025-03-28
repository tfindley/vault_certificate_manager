provider "vault" {
  # It is strongly recommended to configure this provider through the
  # environment variables described above, so that each user can have
  # separate credentials set in the environment.
  #
  # This will default to using $VAULT_ADDR
  # But can be set explicitly
  # address = "http://127.0.0.1:8200"
  # ca_cert_file = "/Users/tristan/dev/ssl/ca/myCA.pem"
}