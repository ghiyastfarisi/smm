# OpenBAO server config (deploy/docker-compose.yml, service openbao). Persistent raft storage, sealed at
# start (Shamir 3-of-5), no UI. The listener is plain HTTP on the private compose network only (port 8200 is bound
# to 127.0.0.1 on the host for operator commands).
# ponytail: no TLS on the internal listener; when OpenBAO runs on a separate host, add tls_cert_file/tls_key_file
# below and set OPENBAO_ADDR=https://… on the server (see README.md "Production profile" §1 and §7).
storage "raft" {
  path    = "/openbao/file"   # the image's data volume, owned by the openbao user
  node_id = "bao-1"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
# Every request (including each read of the root secret) is logged with token accessor and client address.
# Ship this file off the host (README.md §5).
audit "file" "file" {
  options {
    file_path = "/openbao/logs/audit.log"
  }
}
api_addr     = "http://openbao:8200"
cluster_addr  = "http://openbao:8201"
ui            = false
