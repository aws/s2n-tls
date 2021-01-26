# SPEC file overview:
# https://docs.fedoraproject.org/en-US/quick-docs/creating-rpm-packages/#con_rpm-spec-file-overview
# Fedora packaging guidelines:
# https://docs.fedoraproject.org/en-US/packaging-guidelines/


Name:           s2n-tls
Version:        1.0.10
Release:        0%{?dist}
Summary:        A C99 TLS library

License:        Apache2.0
URL:            https://github.com/aws/${name}
%undefine       _disable_source_fetch
Source0:        https://github.com/aws/%{name}/archive/v%{version}.tar.gz
%define         SHA256SUM0  41d6215e73f38eb1970d17f85c7eb683f556f803a608339a76da9030e160bbd6
Patch0:         makefile.patch
Group:          System Environment/Libraries
BuildRequires:  openssl11-static cmake3 ninja-build zlib-devel
Requires:       openssl11-static
%description
A C99 TLS library

%package tls
Summary:        A C99 compatable TLS library
%description tls
s2n is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority.

%package tls-devel
Summary:    Header files for s2n
%description tls-devel
s2n is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority.

%prep
%setup -q
# TODO: remove the patch after the release of this change.
# We need this patch b/c we're pinning the source to a fixed github release, Makefile needs updating for rpmbuild to work.
%patch0 -p1

%build
cmake3 -GNinja -DCMAKE_EXE_LINKER_FLAGS="-lcrypto -lz" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Release .
ninja-build
ninja-build test

%install
%make_install

%files tls
%license LICENSE
/usr/lib64/*

%files tls-devel
/usr/include/*

%changelog
* Mon May 14 2021 Doug Chapman <dougch@amazon.com>
- Inital RPM spec build of v1.0.8
