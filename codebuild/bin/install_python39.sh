set -e

usage() {
    echo "install_python39.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
source codebuild/bin/jobs.sh

cd "$BUILD_DIR"
curl https://www.python.org/ftp/python/3.9.10/Python-3.9.10.tgz > Python-3.9.10.tgz
tar -xzvf Python-3.9.10.tgz
cd Python-3.9.10

apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev
./configure --prefix="$INSTALL_DIR"
make -j $JOBS
make install
