#!/bin/bash

set -xe

usage() {
	echo "install_saw.sh download_dir install_dir"
	exit 1
}

if [ "$#" -ne "2" ]; then
	usage
fi

DOWNLOAD_DIR=$1
INSTALL_DIR=$2

mkdir -p $DOWNLOAD_DIR
cd $DOWNLOAD_DIR

#download saw binaries
curl http://saw.galois.com/builds/nightly/saw-0.2-2017-01-01-Ubuntu14.04-64.tar.gz > saw.tar.gz;

mkdir -p saw && tar -xzf saw.tar.gz --strip-components=1 -C saw
mkdir -p $INSTALL_DIR && mv saw/* $INSTALL_DIR

