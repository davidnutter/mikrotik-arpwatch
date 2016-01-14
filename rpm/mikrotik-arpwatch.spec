#-*-shell-script-*-
%define debug_package %{nil}
Summary: Tool to read ARP data from Mikrotik router API 
Name: mikrotik-arpwatch
Version: 0.2
Release: 1%{?dist}
License: BSD
BuildArch: noarch
Group: Systems/Environment
URL: http://www.bioss.ac.uk/
Source0: %{name}-%{version}.tar.gz
BuildRequires: python
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}

%description
Tool to read ARP data from Mikrotik router API. Required for providing
network accounting information to service provider for billing
purposes.

%prep
%setup -q

%build
python setup.py build

%install
python setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

#Must list this explicity to allow us to set attrs
sed -i -e '/mikrotik-arpwatch.cfg/ d' -e 's/mikrotik-arpwatch.py/mikrotik-arpwatch/' INSTALLED_FILES
%{__install} -d -m 0755 %{buildroot}/var/lib/%{name}
%{__mv} %{buildroot}/%{_bindir}/mikrotik-arpwatch.py %{buildroot}/%{_bindir}/mikrotik-arpwatch

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
 [ -f /var/run/%{name}.pid ] && /sbin/service %{name} stop > /dev/null 2>&1
 /sbin/chkconfig --del %{name}
fi


%files -f INSTALLED_FILES
%defattr(-,root,root,-)
%config(noreplace) %attr(0600,root,root) /etc/mikrotik-arpwatch.cfg
%dir %attr(-,nobody,nobody) /var/lib/mikrotik-arpwatch

%changelog
* Wed Jan 13 2016 David Nutter <david.nutter@bioss.ac.uk> - mikrotik-arpwatch-0.2.el5
- Added functioning keepalive support to detect network errors
* Thu Mar 6 2014 David Nutter <david.nutter@bioss.ac.uk> - mikrotik-arpwatch-0.1.el5
- Initial build
