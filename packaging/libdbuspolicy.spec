Name:           libdbuspolicy-dummy
Summary:        Helper library for fine-grained userspace policy handling
License:        Apache-2.0
Group:          Base/IPC
Version:        1.0.0
Release:        0
Source:         %{name}-%{version}.tar.gz
Source1001:     libdbuspolicy.manifest

%description
libdbuspolicy is a helper library for fine-grained userspace
policy handling (with SMACK support)
.
This version provides dummy version of library.

%prep
%setup -q
cp %{SOURCE1001} .

%build
./autogen.sh
./configure \
    --libdir=%{_libdir}	\
    --prefix=/usr

make

%install
make DESTDIR=%{buildroot} install-strip

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%manifest libdbuspolicy.manifest
%defattr(-,root,root)
%{_includedir}/*

%{_libdir}/pkgconfig/*
%{_libdir}/libdbuspolicy1.so.*
%{_libdir}/libdbuspolicy1.la
%{_libdir}/libdbuspolicy1.so

%changelog
