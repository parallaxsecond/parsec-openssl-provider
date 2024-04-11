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
    CA_PRIV_KEY=${CA_DIRECTORY}/ca_private_key.pem

    # Generate a self signed certificate for the CA along with a key.
    if [ ! -f "${CA_CERTIFICATE}" ]; then
        mkdir -p "${CA_DIRECTORY}" 
        chmod 700 "${CA_DIRECTORY}"

        openssl req -x509 -nodes -newkey rsa:2048 \
            -keyout "${CA_PRIV_KEY}" \
            -out "${CA_CERTIFICATE}" \
            -subj "/C=UK/ST=Parsec /L=Parsec/O=Parsec/CN=parsec.com" > /dev/null 2>&1

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
    SERVER_PRIV_KEY=${SERVER_DIRECTORY}/server_private_key.pem

    CA_DIRECTORY=$2
    CA_CERTIFICATE=${CA_DIRECTORY}/ca_cert.pem
    CA_PRIV_KEY=${CA_DIRECTORY}/ca_private_key.pem

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
            -subj "/C=UK/ST=Parsec /L=Parsec/O=Parsec/CN=parsec.com" > /dev/null 2>&1
        if [ $? -ne 0 ]; then 
            echo "FAILED TO GENERATE CERTIFICATE REQUEST"
            exit 1
        fi

        # Generate certificate
        openssl x509 -req -in "${SERVER_CSR}" \
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

# ToDo: This function needs to be updated to use the parsec-tool 
# for key, CSR generation for hardware backed keys. 
# Generate the client key and certificate signed by CA
# inputs: 
#   client directory
#   certificate directory
generate_client_certs() {
    CLIENT_DIRECTORY=$1
    CLIENT_CERTIFICATE=${CLIENT_DIRECTORY}/client_cert.pem
    CLIENT_CSR=${CLIENT_DIRECTORY}/client_cert.csr
    CLIENT_PRIV_KEY=${CLIENT_DIRECTORY}/client_private_key.pem

    CA_DIRECTORY=$2
    CA_CERTIFICATE=${CA_DIRECTORY}/ca_cert.pem
    CA_PRIV_KEY=${CA_DIRECTORY}/ca_private_key.pem

    if [ ! -f "${CLIENT_CSR}" ]; then
        mkdir -p "${CLIENT_DIRECTORY}" > /dev/null 2>&1
        chmod 700 "${CLIENT_DIRECTORY}"

        # Generate private key
        openssl genrsa -out "${CLIENT_PRIV_KEY}" 2048 > /dev/null 2>&1
        if [ $? -ne 0 ]; then 
            echo "FAILED TO GENERATE KEY"
            exit 1
        fi

        # Generate certificate request
        openssl req -new \
            -key "${CLIENT_PRIV_KEY}" \
            -out "${CLIENT_CSR}" \
            -subj "/C=UK/ST=Parsec /L=Parsec/O=Parsec/CN=parsec.com" > /dev/null 2>&1
        if [ $? -ne 0 ]; then 
            echo "FAILED TO GENERATE CERTIFICATE REQUEST"
            exit 1
        fi

        # Generate certificate
        openssl x509 -req -in "${CLIENT_CSR}" \
            -CA "${CA_CERTIFICATE}" -CAkey "${CA_PRIV_KEY}" \
            -CAcreateserial -out "${CLIENT_CERTIFICATE}" > /dev/null 2>&1
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

echo -n "Generating client private key and certificate: "
generate_client_certs ./tls/client ./tls/ca

echo -n "Generating fake certificate authority private key and certificate: "
generate_ca_certs ./tls/fake_ca

echo -n "Generating fake client private key and certificate: "
generate_client_certs ./tls/fake_client ./tls/fake_ca

exit 0
