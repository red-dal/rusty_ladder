#!/bin/bash
openssl req -nodes \
          -x509 \
          -days 3650 \
          -newkey rsa:4096 \
          -keyout ca.key \
          -out ca.crt \
          -sha256 \
          -batch 

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout localhost.key \
          -out localhost.csr \
          -sha256 \
          -batch \
          -subj "/CN=localhost"


openssl x509 -req \
        -in localhost.csr \
        -out localhost.crt \
        -CA ca.crt \
        -CAkey ca.key \
        -sha256 \
        -days 2000 \
        -CAcreateserial \
        -extfile <(printf "subjectAltName=DNS:localhost")