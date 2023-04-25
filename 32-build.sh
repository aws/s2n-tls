set -e
rm build/ -rf
cmake . \
	-Bbuild \
	-DCMAKE_BUILD_TYPE=DEBUG \
	-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/32-bit.toolchain

cmake --build ./build -j $(nproc)