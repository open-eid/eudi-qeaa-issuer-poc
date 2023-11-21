#!/bin/bash

set -eu

cd "$(command dirname -- "${0}")" || exit

./generate-ca-certificate.sh 'eudi'

./generate-certificate.sh 'eudi-ca' 'eudi-as'
./generate-certificate.sh 'eudi-ca' 'eudi-issuer'
./generate-certificate.sh 'eudi-ca' 'eudi-rp'
./generate-certificate.sh 'eudi-ca' 'eudi-rp-backend'
./generate-certificate.sh 'eudi-ca' 'eudi-wallet'
./generate-certificate.sh 'eudi-ca' 'eudi-wallet-provider'

cp ./eudi-ca/* ../../../eudi-qeaa-as-mock/src/main/resources/
cp ./eudi-ca/* ../../../eudi-qeaa-issuer-poc/src/main/resources
cp ./eudi-ca/* ../../../eudi-qeaa-rp-mock/src/main/resources
cp ./eudi-ca/* ../../../eudi-qeaa-rp-backend-mock/src/main/resources
cp ./eudi-ca/* ../../../eudi-qeaa-wallet-mock/src/main/resources

cp ./eudi-as/* ../../../eudi-qeaa-as-mock/src/main/resources/
cp ./eudi-issuer/* ../../../eudi-qeaa-issuer-poc/src/main/resources
cp ./eudi-rp/* ../../../eudi-qeaa-rp-mock/src/main/resources
cp ./eudi-rp-backend/* ../../../eudi-qeaa-rp-backend-mock/src/main/resources
cp ./eudi-wallet/* ../../../eudi-qeaa-wallet-mock/src/main/resources

cp ./eudi-wallet/*.crt ../../../eudi-qeaa-as-mock/src/main/resources
cp ./eudi-wallet-provider/*.crt ../../../eudi-qeaa-as-mock/src/main/resources
cp ./eudi-wallet-provider/* ../../../eudi-qeaa-wallet-mock/src/main/resources
cp ./eudi-issuer/*.crt ../../../eudi-qeaa-as-mock/src/main/resources
cp ./eudi-issuer/*.crt ../../../eudi-qeaa-rp-mock/src/main/resources
cp ./eudi-issuer/* ../../../eudi-qeaa-wallet-mock/src/main/resources

cp ./eudi-wallet/* ../../../eudi-qeaa-issuer-poc/src/test/resources
cp ./eudi-wallet-provider/* ../../../eudi-qeaa-issuer-poc/src/test/resources
cp ./eudi-as/* ../../../eudi-qeaa-issuer-poc/src/test/resources/
