# The only thing the mrpostman server may do in OpenBAO: read its root secret.
path "secret/data/mrpostman/root" {
  capabilities = ["read"]
}
