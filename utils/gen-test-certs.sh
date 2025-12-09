#!/bin/bash

# Generate some test certificates which are used by the regression test suite:
#
#   test/tls/ca.{crt,key}          Self signed CA certificate.
#   test/tls/redis.{crt,key}       A certificate with no key usage/policy restrictions.
#   test/tls/client.{crt,key}      A certificate restricted for SSL client usage.
#   test/tls/server.{crt,key}      A certificate restricted for SSL server usage.
#   test/tls/redis.dh              DH Params file.

generate_cert() {
    local name=$1
    local cn="$2"
    local opts="$3"

    local keyfile=test/tls/${name}.key
    local certfile=test/tls/${name}.crt

    [ -f $keyfile ] || openssl genrsa -out $keyfile 2048
    openssl req \
        -new -sha256 \
        -subj "/O=Redis Test/CN=$cn" \
        -key $keyfile | \
        openssl x509 \
            -req -sha256 \
            -CA test/tls/ca.crt \
            -CAkey test/tls/ca.key \
            -CAserial test/tls/ca.txt \
            -CAcreateserial \
            -days 365 \
            $opts \
            -out $certfile
}

mkdir -p test/tls
[ -f test/tls/ca.key ] || openssl genrsa -out test/tls/ca.key 4096
openssl req \
    -x509 -new -nodes -sha256 \
    -key test/tls/ca.key \
    -days 3650 \
    -subj '/O=Redis Test/CN=Certificate Authority' \
    -out test/tls/ca.crt

cat > test/tls/openssl.cnf <<_END_
[ server_cert ]
keyUsage = digitalSignature, keyEncipherment
nsCertType = server

[ client_cert ]
keyUsage = digitalSignature, keyEncipherment
nsCertType = client
_END_

generate_cert server "Server-only" "-extfile test/tls/openssl.cnf -extensions server_cert"
generate_cert client "Client-only" "-extfile test/tls/openssl.cnf -extensions client_cert"
generate_cert redis "Generic-cert"

[ -f test/tls/redis.dh ] || openssl dhparam -out test/tls/redis.dh 2048
