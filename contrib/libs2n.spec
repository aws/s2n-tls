Summary: s2n is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority.
Name: libs2n
Version: 20150703
Release: 1%{?dist}%{?extra_release}
License: Apache 2.0
Group: Development/Libraries
Vendor: Amazon.com, Inc.
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-%{version}-root
URL: https://github.com/awslabs/s2n
Source: libs2n-%{version}.tar.gz
BuildRequires: glibc-devel
Requires: glibc
Requires: zlib

%description
%{summary}

%package devel
Summary: Libraries, includes, etc. to compile with the libs2n library.
Group: Development/Libraries
Requires: libs2n = %{version}

%description devel
Includes and documentations for the C++ libs2n library.

%prep
%setup

%build
make %{?_smp_mflags} libs

%install
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -fr "${RPM_BUILD_ROOT}"
install -D -m 0755 api/s2n.h ${RPM_BUILD_ROOT}%{_includedir}/s2n.h
install -D -m 0755 lib/libs2n.so ${RPM_BUILD_ROOT}%{_libdir}/libs2n.so
install -D -m 0755 lib/libs2n.a ${RPM_BUILD_ROOT}%{_libdir}/libs2n.a
install -D -m 0755 contrib/libs2n.pc ${RPM_BUILD_ROOT}%{_libdir}/pkgconfig/libs2n.pc

%clean 
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -fr "${RPM_BUILD_ROOT}"

%post
umask 007

if test -d "/etc/ld.so.conf.d"; then
  CONFFILE="/etc/ld.so.conf.d/%{name}.conf"
  if test ! -f "${CONFFILE}"; then # create
    echo "%{_libdir}" >> "${CONFFILE}"
  fi
else
  CONFFILE="/etc/ld.so.conf"
  if ! grep -q "%{_libdir}" "${CONFFILE}"; then # append
    echo "%{_libdir}" >> "${CONFFILE}"
  fi
fi

/sbin/ldconfig > /dev/null 2>&1

%preun

%postun
CONFFILE="/etc/ld.so.conf.d/%{name}.conf"

if test -f "${CONFFILE}"; then
  rm -f "${CONFFILE}"
fi

/sbin/ldconfig > /dev/null 2>&1

%files
%defattr(-, root, root)
%doc LICENSE NOTICE README.md docs
%{_libdir}/*.a
%{_libdir}/*.so*

%files devel
%defattr(-, root, root)
%{_includedir}/*.h
%{_libdir}/pkgconfig/*.pc

%changelog
* Fri Jul 3 2015 James M. Sella <sella@digitalgenesis.com> - 20150703
- Initial packaging of libs2n.
