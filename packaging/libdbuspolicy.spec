Name:           libdbuspolicy
Summary:        Helper library for fine-grained userspace policy handling
License:        Apache-2.0
Group:          Base/IPC
Version:        1.0.0
Release:        0
Source:         %{name}-%{version}.tar.gz
Source1001:     %{name}.manifest
BuildRequires:  boost-devel
BuildRequires:  pkgconfig(cynara-client)


%package devel
Summary:        Helper library for fine-grained userspace policy handling-development package
Requires:       %{name} = %{version}

%description
libdbuspolicy is a helper library for fine-grained userspace
policy handling (with SMACK support)

%description devel
libdbuspolicy is a helper library for fine-grained userspace
policy handling (with SMACK support). This package contains
development files.

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
rm %{buildroot}%{_libdir}/libdbuspolicy1.la

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%{_libdir}/libdbuspolicy1.so.*
%manifest %{name}.manifest

%files devel
%defattr(-,root,root)
%{_includedir}/*

%{_libdir}/pkgconfig/*
%{_libdir}/libdbuspolicy1.so
%manifest %{name}.manifest

%changelog
