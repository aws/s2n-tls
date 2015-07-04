#!/bin/sh
#set -vx

PROGRAM="libs2n"
VERSION="20150703"

BUILDNAME="${PROGRAM}-${VERSION}"
SPECFILE="${PROGRAM}.spec"

DIRECTORY=""
RPMBUILD_ARGS="-ba"

while [ $# -gt 0 ]; do
	if [ -d "$1" ]; then
		DIRECTORY=$1
	fi

	shift
done

if [ ! -d "$DIRECTORY" ]; then
	printf "./%s <package directory>\n" `basename $0`
	printf "\nExample: trunk/contrib/%s trunk\n" ${PROGRAM} `basename $0` ${PROGRAM}

	exit 1
fi

if [ ! -f "$DIRECTORY/contrib/${SPECFILE}" ]; then
	printf "Failed to locate SPEC file at %s.\n" "$1/contrib/${SPECFILE}"

	exit 1
fi

DIRNAME="`dirname $DIRECTORY`"
BASENAME="`basename $DIRECTORY`"
SPECFULL="${BASENAME}/contrib/${SPECFILE}"

# Move to base directory
cd ${DIRNAME}

# Trap cleanup
trap 'rm -rf rpm; exit' INT

# Setup RPM build directory
if [ ! -d rpm ]; then
	mkdir -p rpm/BUILD rpm/RPMS rpm/SOURCES rpm/SPECS rpm/SRPMS rpm/tmp
	cp "${SPECFULL}" rpm/SPECS/
else
	printf "%s already exists. Exiting.\n" "${DIRNAME}/rpm"

	exit 1
fi

# Remove generated files
(cd ${BASENAME} && make distclean)

# Trap cleanup
trap 'rm -rf rpm; mv "${BUILDNAME}" "${BASENAME}"; exit' INT

# Set directory to build name
mv "${BASENAME}" "${BUILDNAME}"

# Create source tarball
tar cvzf rpm/SOURCES/${BUILDNAME}.tar.gz --exclude 'core.*' --exclude 'vgcore.*' --exclude-vcs ${BUILDNAME}

# Restore original directory name
mv "${BUILDNAME}" "${BASENAME}"

# Trap cleanup
trap 'rm -rf rpm; exit' INT

(cd rpm && rpmbuild --define "_topdir `pwd`" --define "_tmppath `pwd`/tmp" "${ARGS[@]}" ${RPMBUILD_ARGS} SPECS/${SPECFILE})

# Display results
for RPM in `find rpm -name "*.rpm"`; do
	printf "\n[%s]\n" `basename "${RPM}"`
	rpm -qpi ${RPM}
	rpm -qpl ${RPM}
	echo
done

# Copy RPMs
find rpm -name "*.rpm" -exec cp {} `pwd` \;

# Cleanup
rm -rf rpm
