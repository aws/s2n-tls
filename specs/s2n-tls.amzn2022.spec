# SPEC file overview:
# https://docs.fedoraproject.org/en-US/quick-docs/creating-rpm-packages/#con_rpm-spec-file-overview
# Fedora packaging guidelines:
# https://docs.fedoraproject.org/en-US/packaging-guidelines/


Name:           s2n-tls
Version:        1.3.4
Release:        0%{?dist}
Summary:        A C99 TLS library

License:        Apache2.0
URL:            https://github.com/aws/${name}
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Group:          System Environment/Libraries
BuildRequires:  gcc openssl-devel cmake ninja-build
Requires:       openssl
Requires:       %{name}-libs%{?_isa} = 0:%{version}-%{release}

# Don't include test binaries
%bcond_with test

%description
A C99 TLS library

%package libs
Summary:        A C99 compatable TLS library
%description libs
s2n-tls is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority.

%package devel
Summary:    Header files for s2n
%description devel
Header files for s2n-tls, a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority.

%prep
%autosetup

%build
%cmake -DBUILD_SHARED_LIBS=ON
%cmake_build

%install
%cmake_install

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files libs
%defattr(-,root,root)
%license LICENSE
%attr(755,root,root) %{_libdir}/libs2n.so

%if %{with test}
%attr(755,root,root) %{_bindir}/s2n*
%endif

%files devel
%{_includedir}/*.h
%{_libdir}/cmake/s2n/modules/FindLibCrypto.cmake
%{_libdir}/cmake/s2n/s2n-config.cmake
%{_libdir}/cmake/s2n/shared/s2n-*.cmake
%{_libdir}/pkgconfig/s2n-tls.pc

%changelog
* Thu Jan 20 2022 Doug Chapman <dougch@amazon.com>
- Inital RPM spec build of v1.3.4
