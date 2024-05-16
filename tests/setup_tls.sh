#!/usr/bin/env bash

# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
#
# This script generates the certificates and keys for CA, server
# and the client required for TLS handshake.


# Generate the CA key and self signed certificate
# inputs:
#   certificate directory
generate_ca_certs() {
    CA_DIRECTORY=$1
    CA_CERTIFICATE=${CA_DIRECTORY}/ca_cert.pem
    CA_PRIV_KEY=${CA_DIRECTORY}/ca_priv_key.pem

    # Generate a self signed certificate for the CA along with a key.
    if [ ! -f "${CA_CERTIFICATE}" ]; then
        mkdir -p "${CA_DIRECTORY}" 
        chmod 700 "${CA_DIRECTORY}"

        openssl req -x509 -nodes -days 1000 -newkey rsa:2048 \
            -keyout "${CA_PRIV_KEY}" \
            -out "${CA_CERTIFICATE}" \
            -subj "/C=UK/ST=Parsec /L=Parsec/O=Parsec/CN=parsec_ca.com" > /dev/null 2>&1

        if [ $? -ne 0 ]; then 
            echo "FAILED"
            exit 1
        fi
        echo "SUCCESS"
    else
        echo "SKIPPED"
    fi
}

# Generate the server key and certificate signed by CA
# inputs:
#   server directory
#   certificate directory
generate_server_certs() {
    SERVER_DIRECTORY=$1
    SERVER_CERTIFICATE=${SERVER_DIRECTORY}/server_cert.pem
    SERVER_CSR=${SERVER_DIRECTORY}/server_cert.csr
    SERVER_PRIV_KEY=${SERVER_DIRECTORY}/server_priv_key.pem

    CA_DIRECTORY=$2
    CA_CERTIFICATE=${CA_DIRECTORY}/ca_cert.pem
    CA_PRIV_KEY=${CA_DIRECTORY}/ca_priv_key.pem

    if [ ! -f "${SERVER_CSR}" ]; then
        mkdir -p "${SERVER_DIRECTORY}" > /dev/null 2>&1
        chmod 700 "${SERVER_DIRECTORY}"

        # Generate private key
        openssl genrsa -out "${SERVER_PRIV_KEY}" 2048 > /dev/null 2>&1
        if [ $? -ne 0 ]; then 
            echo "FAILED TO GENERATE KEY"
            exit 1
        fi

        # Generate certificate request
        openssl req -new \
            -key "${SERVER_PRIV_KEY}" \
            -out "${SERVER_CSR}" \
            -subj "/C=UK/ST=Parsec /L=Parsec/O=Parsec/CN=parsec_server.com" > /dev/null 2>&1
        if [ $? -ne 0 ]; then 
            echo "FAILED TO GENERATE CERTIFICATE REQUEST"
            exit 1
        fi

        # Generate certificate
        openssl x509 -req -days 1000 -in "${SERVER_CSR}" \
            -CA "${CA_CERTIFICATE}" -CAkey "${CA_PRIV_KEY}" \
            -CAcreateserial -out "${SERVER_CERTIFICATE}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then 
            echo "FAILED"
            exit 1
        fi

        echo "SUCCESS"
    else
        echo "SKIPPED"
    fi
}

# use the parsec-tool for key, CSR generation for hardware backed keys.
# Generate the client key and certificate signed by CA
# inputs:
#   client directory
#   certificate directory
#   certificate request name (without extension)
#   name of parsec key
generate_client_certs_parsec() {
    CLIENT_DIRECTORY=$1
    CLIENT_CERTIFICATE=${CLIENT_DIRECTORY}/$3.pem
    CLIENT_CSR=${CLIENT_DIRECTORY}/$3.csr

    CA_DIRECTORY=$2
    CA_CERTIFICATE=${CA_DIRECTORY}/ca_cert.pem
    CA_PRIV_KEY=${CA_DIRECTORY}/ca_priv_key.pem

    if [ ! -f "${CLIENT_CSR}" ]; then
        mkdir -p "${CLIENT_DIRECTORY}" > /dev/null 2>&1
        chmod 700 "${CLIENT_DIRECTORY}"

        # Generate certificate request via Parsec
        parsec-tool create-csr --cn parsec_client.com --l Parsec --c UK --st Parsec --o Parsec --key-name $4 > ${CLIENT_CSR}

        # Generate certificate
        openssl x509 -req -days 1000 -in "${CLIENT_CSR}" \
            -CA "${CA_CERTIFICATE}" -CAkey "${CA_PRIV_KEY}" \
            -CAcreateserial -out "${CLIENT_CERTIFICATE}"
        if [ $? -ne 0 ]; then 
            echo "FAILED"
            exit 1
        fi

        echo "SUCCESS"
    else
        echo "SKIPPED"
    fi
}

echo -n "Generating certificate authority private key and certificate: "
generate_ca_certs ./tls/ca

echo -n "Generating server private key and certificate: "
generate_server_certs ./tls/server ./tls/ca

echo -n "Generating client certificate: "
generate_client_certs_parsec ./tls/client ./tls/ca parsec_rsa PARSEC_TEST_RSA_KEY
generate_client_certs_parsec ./tls/client ./tls/ca parsec_ecdsa PARSEC_TEST_ECDSA_KEY

echo -n "Generating fake certificate authority private key and certificate: "
generate_ca_certs ./tls/fake_ca

echo -n "Generating fake client certificate: "
generate_client_certs_parsec ./tls/fake_client ./tls/ca parsec_rsa PARSEC_FAKE_RSA_KEY
generate_client_certs_parsec ./tls/fake_client ./tls/ca parsec_ecdsa PARSEC_FAKE_ECDSA_KEY

exit 0
