
RPMSOURCES=~/rpmbuild/SOURCES
RPMS=~/rpmbuild/RPMS
ARCHIVE=s2n-tls.tgz

.PHONY : all
all: 

$(RPMSOURCES):
	mkdir -p $@

$(RPMSOURCES)/$(ARCHIVE): $(RPMSOURCES)
	git archive --format=tgz -o $@ HEAD

$(RPMS)/$(ARCH)/$(NAME)-lib*.rpm: $(RPMSOURCES)
	rpmbuild -ba ./srpms/s2n-tls.spec
