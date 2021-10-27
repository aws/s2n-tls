# SPEC file overview:
# https://docs.fedoraproject.org/en-US/quick-docs/creating-rpm-packages/#con_rpm-spec-file-overview
# Fedora packaging guidelines:
# https://docs.fedoraproject.org/en-US/packaging-guidelines/


Name:           s2n-tls
Version:        1.1.1
Release:        0%{?dist}
Summary:        A C99 TLS library

License:        Apache2.0
URL:            https://github.com/aws/${name}
Source0:        https://github.com/aws/%{name}/archive/v%{version}.tar.gz
Group:          System Environment/Libraries
BuildRequires:  openssl11-static cmake3 ninja-build zlib-devel
Requires:       openssl11-static
%description
A C99 TLS library

%package tls
Summary:        A C99 compatable TLS library
%description tls
s2n-tls is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority.

%package tls-devel
Summary:    Header files for s2n
%description tls-devel
Header files for s2n-tls, a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority.

%prep
%setup -q

%build
cmake3 -GNinja -DCMAKE_EXE_LINKER_FLAGS="-lcrypto -lz" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Release .
ninja-build
ninja-build test

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%install
mkdir -p %{buildroot}%{_libdir}/
mkdir -p %{buildroot}%{_includedir}/
install lib/*.{so,a} %{buildroot}%{_libdir}/


%files tls
%defattr(-,root,root)
%license LICENSE
%attr(755,root,root) %{_libdir}/libs2n.so

%files tls-devel
%{_includedir}/*.h

 %files tls-static
 %attr(0644,root,root) %{_libdir}/libs2n.a

%changelog
* Mon May 14 2021 Doug Chapman <dougch@amazon.com>
- Inital RPM spec build of v1.1.1
