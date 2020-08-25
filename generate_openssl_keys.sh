#!/bin/bash
mkdir certs
openssl genrsa -out idm-2020-key.pem 2048
openssl req -new -sha256 -key idm-2020-key.pem -out idm-2020-csr.pem
openssl x509 -req -in idm-2020-csr.pem -signkey idm-2020-key.pem -out idm-2020-cert.pem
mv idm-2020-key.pem idm-2020-cert.pem idm-2020-csr.pem certs/
