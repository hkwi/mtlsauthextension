#!/bin/bash
set -e

# Directory for generated certs
CERTDIR=$(dirname "$0")/certs
mkdir -p "$CERTDIR"
pushd "$CERTDIR"

# Generate CA configs

# Add 'localhost' to hosts for all CAs and certs
cat > ca_server.json <<EOF
{
  "CN": "test_server_ca",
  "hosts": ["localhost"],
  "key": {"algo": "rsa", "size": 2048},
  "names": [{"C": "JP", "O": "TestOrg"}]
}
EOF

cat > ca_client.json <<EOF
{
  "CN": "test_client_ca",
  "hosts": ["localhost"],
  "key": {"algo": "rsa", "size": 2048},
  "names": [{"C": "JP", "O": "TestOrg"}]
}
EOF

# Generate server CA
cfssl gencert -initca ca_server.json | cfssljson -bare server_ca
# Generate client CA
cfssl gencert -initca ca_client.json | cfssljson -bare client_ca

# Server certificate CSR
cat > server_csr.json <<EOF
{
  "CN": "test_server",
  "hosts": ["localhost"],
  "key": {"algo": "rsa", "size": 2048},
  "names": [{"C": "JP", "O": "TestOrg"}]
}
EOF

# Client certificate CSR
cat > client_csr.json <<EOF
{
  "CN": "test_client",
  "hosts": ["localhost"],
  "key": {"algo": "rsa", "size": 2048},
  "names": [{"C": "JP", "O": "TestOrg"}]
}
EOF

# Generate server certificate signed by server CA
cfssl gencert -ca=server_ca.pem -ca-key=server_ca-key.pem -config=<(
  echo '{"signing":{"default":{"usages":["signing","key encipherment","server auth"],"expiry":"8760h"}}}') \
  -profile=default server_csr.json | cfssljson -bare server

# Generate client certificate signed by client CA
cfssl gencert -ca=client_ca.pem -ca-key=client_ca-key.pem -config=<(
  echo '{"signing":{"default":{"usages":["signing","key encipherment","client auth"],"expiry":"8760h"}}}') \
  -profile=default client_csr.json | cfssljson -bare client

# Output summary
popd
ls -l "$CERTDIR"
echo "Certificates generated in $CERTDIR"
