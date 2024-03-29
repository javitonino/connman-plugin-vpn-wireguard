Name:          connman-plugin-vpn-wireguard
Summary:       Connman plugin for Wireguard VPN
Version:       0.5
Release:       1
License:       GPLv3
Requires:      connman >= 1.32+git193
Requires:      wireguard-go
Requires:      wireguard-tools
Requires:      glib2 >= 2.28
BuildRequires: connman-devel >= 1.32
BuildRequires: pkgconfig(glib-2.0) >= 2.28

%description

%build
rm -f wireguard.so
gcc `pkg-config --cflags --libs glib-2.0 dbus-1` -DSCRIPTDIR=\"%{_libdir}/connman/scripts\" -fPIC -shared wireguard_plugin.c -o wireguard.so

%install
rm -rf %{buildroot}

install -d %{buildroot}%{_libdir}/connman/plugins-vpn
install wireguard.so %{buildroot}%{_libdir}/connman/plugins-vpn

install -d %{buildroot}%{_libdir}/connman/scripts
install wireguard.sh %{buildroot}%{_libdir}/connman/scripts

install -d %{buildroot}%{_sysconfdir}/connman/vpn-plugin
install wireguard.conf %{buildroot}%{_sysconfdir}/connman/vpn-plugin

%files
%defattr(-,root,root,-)
%defattr(0644,root,root,-)
%{_libdir}/connman/plugins-vpn/wireguard.so
%attr(755,root,root) %{_libdir}/connman/scripts/wireguard.sh
%{_sysconfdir}/connman/vpn-plugin/wireguard.conf

%changelog
* Mon Feb 13 2023 javitonino <> - 0.5-1
- Support Sailfish OS 4.5

* Thu Dec 1 2022 javitonino <> - 0.4-1
- Support preshared keys

* Sat Nov 12 2022 javitonino <> - 0.3-1
- Generate routes for allowed IPs

* Mon Nov 7 2022 javitonino <> - 0.2-1
- Fix VPN gateway so a route is correctly generated for the VPN server
