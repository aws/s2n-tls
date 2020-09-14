# Makefile for wrapping docker commands
/etc/os-release:
	@yum install -y lsb-release
openssl:
	@yum install -y openssl11-static
python3:
	@yum install -y python3 python3-dev python3-pip
gcc:
	@yum install -y gcc
libffi:
	@yum install -y libffi-devel
/usr/local/bin/docker-compose: gcc python3 libffi openssl /etc/os-release
	@python3 -m pip install docker-compose
	@chmod 755 /usr/local/bin/docker-compose


