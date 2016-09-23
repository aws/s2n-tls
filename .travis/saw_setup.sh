#!/bin/bash
#setup travis environment for saw

curl http://saw.galois.com/builds/nightly/saw-0.2-2016-09-22-Ubuntu14.04-64.tar.gz > saw.tar.gz
tar -xzvf saw.tar.gz
export PATH=$PATH:$PWD/saw-0.2-2016-09-22-Ubuntu14.04-64/bin

# Install Z3
mkdir z3
curl http://saw.galois.com/builds/z3/z3 > z3/z3
sudo chmod +x z3/z3
export PATH=$PWD/z3:$PATH
