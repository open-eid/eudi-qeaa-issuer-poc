#!/bin/bash

set -eu

cd tls || exit
./clean-certificates.sh
./generate-certificates.sh

echo "--------------------------- All resources generated"

# Prevents script window to be closed after completion
echo -e "\nPress any key to exit the script."
read -rn1
