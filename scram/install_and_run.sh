#!/bin/bash

sudo apt-get install python3 
sudo apt-get install python3-pip

pip3 install --user cryptography
pip3 install --user pycryptodome
pip3 install --user pycryptodomex

python3 aes_scram.py

